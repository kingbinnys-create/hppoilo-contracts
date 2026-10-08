#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Registry Contract
//!
//! The backbone of the protocol and its single source of truth. The registry
//! records, per organization:
//! - the **owner** of the organization,
//! - the **module address** for each [`ModuleKind`] (wallet, treasury, policy…),
//!
//! and, globally, a **version → address** table used by the upgrade strategy so
//! new contract versions (e.g. Wallet v1 → v2 → v3) can be introduced without
//! breaking consumers (PRD Doc 7 §Upgrade Strategy).
//!
//! Security model (PRD Doc 10): validate caller → ownership → inputs →
//! permissions → fail safely → emit events. All mutating calls are admin- or
//! owner-gated and require Soroban auth.
//!
//! ## Permission delegation
//!
//! Requiring the root owner's key for every registry edit does not survive
//! contact with a real organization: the people who rotate a policy contract
//! are usually not the people who hold ultimate ownership, and handing them the
//! root key to do it defeats the point of having one. The registry therefore
//! records a [`RegistryRole`] per `(organization, account)` and checks it on the
//! org-scoped modifications, so an owner can delegate narrow administrative
//! powers to sub-accounts or secondary operational keys without transferring
//! ownership:
//!
//! | Role               | May register/remove modules of kind                |
//! |--------------------|----------------------------------------------------|
//! | `Owner`            | any kind (a delegated co-owner for module records) |
//! | `ModuleUpgrader`   | any kind (repointing modules at new versions)      |
//! | `PolicyManager`    | `Policy`                                           |
//! | `TreasuryOperator` | `Treasury`, `Budget`, `Escrow`                     |
//!
//! Delegation is deliberately bounded. Root actions — transferring ownership,
//! the emergency freeze, and administering roles themselves — stay with the
//! recorded org owner and the protocol admin, so no grant can be used to
//! escalate into ownership or to widen its own reach.
//!
//! ## Upgrade paths
//!
//! [`RegistryContract::register_version`] publishes immutable `(kind, version)`
//! records, but a published version is only *reachable* once some organization's
//! module is moved onto it. [`RegistryContract::upgrade_module`] is that move,
//! and it never takes an address or a WASM hash from the caller: it resolves
//! both from the version record itself, so the code a module ends up running is
//! always code the protocol admin published *and* approved. The validations it
//! runs before touching the pointer are, in order:
//!
//! | Check                                              | Refusal                |
//!|----------------------------------------------------|------------------------|
//! | the registry is not frozen                          | `RegistryFrozen`       |
//! | `caller` holds a role that reaches this `kind`      | `Unauthorized`         |
//! | the module is already registered                    | `NotFound`             |
//! | `target_version` is non-zero                        | `InvalidInput`         |
//! | `target_version` is newer than the module's pin     | `CircularUpgrade`      |
//! | the target version exists                           | `NotFound`             |
//! | the target is bound to a WASM hash                  | `InvalidInput`         |
//! | that hash is still approved for this `kind`         | `Unauthorized`         |
//! | the target address is a contract                    | `InvalidInput`         |
//! | the target address is not the one already in use    | `CircularUpgrade`      |
//!
//! [`RegistryContract::register_module_version`] applies the same checks when a
//! module is *registered* rather than moved: it resolves the address and the
//! WASM hash from the version record and advances the pin in the same write, so a
//! versioned deployment (`v1` straight from the registry) is validated at
//! creation time, and a repoint driven through registration cannot walk backwards
//! either.
//!
//! The pin is a high-water mark and version records are immutable, so a module's
//! version sequence is strictly increasing: no upgrade can re-enter a version a
//! module has already left, which is the cycle a rolling deployment must never
//! make. The address check closes the remaining degenerate case, a "move" onto
//! the contract the module already runs. Note what this is and is not: the pin
//! orders the upgrade path, it does not vet the pointer itself.
//! [`RegistryContract::register_module`] remains the unvalidated path that lets
//! an owner or delegate route their own organization's module anywhere, behind
//! the same permission gate as always — resetting the pin is not a new
//! capability, it just keeps the validated path's ordering honest about the
//! code the module is actually running.
//!
//! ## The registry's own upgrade path
//!
//! The registry is the only module in the protocol it cannot delegate the
//! ordering of. Every other contract is moved forward by
//! [`RegistryContract::upgrade_module`], but the registry's own code is replaced
//! through [`astroid_shared`]'s shared upgrade gate, which takes a bare WASM hash
//! and checks exactly two things: that the caller is the recorded upgrade admin,
//! and that the hash is approved for [`ModuleKind::Organization`]. Neither is a
//! statement about ordering. An approved hash stays approved for as long as some
//! deployment needs it, so the hash of the *previous* registry is approved
//! exactly as long as the current one is — and a hash nobody published for this
//! registry is approved on the same terms. Left there, the single source of truth
//! can be rolled back to a superseded set of rules, or moved onto code the
//! upgrade map has never vouched for.
//!
//! [`RegistryContract::upgrade`] therefore resolves the requested hash *back*
//! through the version upgrade map to the published `Organization` version that
//! carries it, and only then decides, against [`DataKey::RegistryVersion`]:
//!
//! | Check                                            | Refusal            |
//! |--------------------------------------------------|--------------------|
//! | the caller is the upgrade admin and has signed   | `Unauthorized`     |
//! | the hash is approved for `Organization`          | `Unauthorized`     |
//! | an `Organization` version has been published     | `NotFound`         |
//! | some published version carries this exact hash   | `NotFound`         |
//! | that version is strictly newer than the running  | `CircularUpgrade`  |
//! | its record names a contract, not an account      | `InvalidInput`     |
//!
//! Resolution runs newest-version-first, so the version a hash maps to is the
//! highest one carrying it, and the ordering check is the same high-water-mark
//! guarantee modules get from [`DataKey::ModuleVersion`]. A registry deployed
//! before this key reads as version `0` and so accepts any published version as
//! its first step, with no migration. Because the version is *derived* from the
//! hash rather than supplied alongside it, there is no argument a caller can
//! pass to claim a forward move while installing backwards code.
//! [`RegistryContract::validate_registry_upgrade`] runs the map checks and
//! nothing else — no auth, no code swap — so a deployer can confirm a target
//! advances the registry before asking for the swap.

use astroid_interfaces::{RegistryInterface, UpgradeableInterface};
use astroid_shared::constants::{
    MAX_APPROVERS, MAX_REGISTRY_BATCH, MAX_UPGRADE_AUDIT_ENTRIES, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD, UPGRADE_PROPOSAL_EXPIRY,
};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::events::{self, ContractEvent, UpgradeAudit};
use astroid_shared::types::{ModuleId, ModuleInfo, ModuleKind};
use astroid_shared::validation::{require_non_empty, require_valid_wasm_hash};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, BytesN, Env, String, Vec,
};

/// How many of the most recently published `Organization` versions the registry
/// scans when resolving an upgrade hash to the version that published it (see
/// [`RegistryContract::plan_registry_upgrade`]).
///
/// The scan runs from the newest published version backwards and normally stops
/// on the first or second entry, so this is a bound rather than a budget. It
/// exists so that one upgrade's cost is a function of the protocol's constant
/// and not of how large a version number an admin chose to publish: an
/// unconstrained walk from `u32::MAX` down to `1` would be a resource-exhaustion
/// hazard in the one entrypoint nobody can afford to have hang. A target bound
/// to a version further behind than this window is reported as
/// [`Error::NotFound`] — the registry is never that far behind in practice, and
/// a rolling deployment advances the latest version first.
const MAX_UPGRADE_SCAN: u32 = 64;

/// Storage keys. `Admin` lives in instance storage; everything else is keyed
/// per organization/module in persistent storage.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Protocol admin (instance).
    Admin,
    /// Authorized multi-admin principals (instance).
    Admins,
    /// Designated multi-signature governance contract (instance).
    Multisig,
    /// Organization owner: org slug -> owner address.
    Org(String),
    /// Module address: (org slug, kind) -> contract address.
    Module(String, ModuleKind),
    /// Module deprecation flag: (org slug, kind) -> bool. When set, the routing
    /// surface (`lookup`) rejects new interactions with [`Error::ModuleDeprecated`]
    /// while the raw address stays readable for legacy migrations.
    ModuleDeprecated(String, ModuleKind),
    /// Version pin: (org slug, kind) -> the version the module currently runs.
    ///
    /// The high-water mark of that module's upgrade path. Absent for every
    /// module registered before validated upgrades existed — those read as `0`
    /// (unpinned) rather than failing, which is what lets an organization
    /// upgrade a module that predates this key without a migration. Cleared by
    /// [`RegistryContract::register_module`] and
    /// [`RegistryContract::remove_module`] together with the record it belongs
    /// to, because both mean "the previous upgrade path describes code this
    /// module no longer runs".
    ModuleVersion(String, ModuleKind),
    /// Delegated role: (org slug, account) -> RegistryRole.
    OrgRole(String, Address),
    /// Legacy version table: (kind, version) -> contract address. Superseded by
    /// [`DataKey::VersionRecord`]; still written by nothing and read only as a
    /// fallback by [`RegistryContract::read_version`], so entries published
    /// before the consolidation keep resolving.
    Version(ModuleKind, u32),
    /// Consolidated version record: (kind, version) -> address + bound WASM
    /// hash. Replaces the former `Version` + `VersionWasm` pair; `Version` is
    /// retained as the legacy layout (see [`RegistryContract::read_version`]).
    VersionRecord(ModuleKind, u32),
    /// Latest known version number for a kind.
    LatestVersion(ModuleKind),
    /// Emergency freeze status (instance).
    Frozen,
    /// Approved WASM hashes: (kind, hash) -> bool.
    ApprovedWasm(ModuleKind, BytesN<32>),
    /// Pending version-upgrade proposal: kind -> UpgradeProposal.
    UpgradeProposal(ModuleKind),
    /// Immutable historical log of upgrade-lifecycle actions (instance).
    UpgradeAuditLog,
    /// The published `Organization` version whose code this contract is
    /// currently running (instance).
    ///
    /// The registry's own high-water mark, and the one that matters most: this
    /// contract is the single source of truth, so an upgrade that moves it onto
    /// older code hands the whole protocol back to a superseded set of rules.
    /// Absent for a registry deployed before the version upgrade map tracked its
    /// own version, which reads as `0` — the same "nothing is pinned yet"
    /// convention [`DataKey::ModuleVersion`] uses, and why no migration is
    /// needed to adopt this key. Written only by
    /// [`RegistryContract::upgrade`], and only ever with a value strictly
    /// greater than the one it read.
    RegistryVersion,
}

/// A pending version-upgrade proposal for one [`ModuleKind`]: the `(version,
/// wasm_hash, address)` triple an authorized caller wants committed into the
/// version table, plus who proposed it and when it expires.
///
/// The record is keyed by kind alone — one proposal per kind at a time — so a
/// kind's upgrade path is always unambiguous and a hostile proposal cannot hide
/// behind a second, conflicting one.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposal {
    /// The version number this proposal would occupy in the version table.
    pub version: u32,
    /// The Wasm hash of the proposed implementation.
    pub wasm_hash: BytesN<32>,
    /// The contract address the implementation is expected to be deployed at.
    pub address: Address,
    /// The organization the proposal was made under. Recorded so the org's
    /// owner can reject (or withdraw via the proposer) a proposal they no
    /// longer want without relying on the protocol admin.
    pub org: String,
    /// Who proposed the upgrade (an org owner or the protocol admin).
    pub proposer: Address,
    /// Unix timestamp after which the proposal can no longer be committed.
    pub expires_at: u64,
}

/// What kind of upgrade-lifecycle action an [`UpgradeAuditRecord`] captures.
/// Discriminants are part of the public ABI and MUST NOT be reordered or
/// reused once released.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeAction {
    /// A `(version, wasm_hash, address)` triple was proposed for a kind.
    Proposed = 0,
    /// A pending proposal was committed into the version table.
    Committed = 1,
    /// A pending proposal was rejected or withdrawn by its proposer.
    Rejected = 2,
}
// NOTE: refused upgrade attempts (unauthorized actor, downgrade, identical-WASM
// re-proposal, …) are deliberately *not* logged. A Soroban invocation is
// atomic: every storage write and event of a call that returns an error is
// rolled back, so an audit entry written on the failure path could never be
// observed on-chain. Refusals stay visible off-chain as reverted transactions
// carrying their error code; the on-chain trail records successful lifecycle
// actions only.

/// One immutable entry in the registry's historical upgrade log (Issue #300):
/// who did what to which version of a module kind, and when. Records are
/// appended on every successful propose/commit/reject and never edited or
/// removed; refused attempts revert atomically (see [`UpgradeAction`]) so the
/// log only ever contains actions that took effect. The log itself is a ring
/// buffer capped at [`MAX_UPGRADE_AUDIT_ENTRIES`] entries of instance storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAuditRecord {
    /// Which lifecycle action was taken.
    pub action: UpgradeAction,
    /// The typed audit payload shared with the emitted event.
    pub audit: UpgradeAudit,
}

/// A delegated administrative role over one organization's registry records.
///
/// One role per account keeps the ledger footprint to a single small entry per
/// delegation. Roles are capability-scoped rather than ranked: `PolicyManager`
/// is not "less" than `TreasuryOperator`, it simply reaches different module
/// kinds. Discriminants are part of the public ABI and MUST NOT be reordered or
/// reused once released.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRole {
    /// Delegated co-owner of the organization's module records. Reaches every
    /// module kind, but not the root actions (ownership transfer, freeze, role
    /// administration), which stay with the recorded owner.
    Owner = 0,
    /// May manage the organization's `Policy` module registration.
    PolicyManager = 1,
    /// May manage the organization's `Treasury`, `Budget` and `Escrow` module
    /// registrations — the value-custody side of the protocol.
    TreasuryOperator = 2,
    /// May repoint any of the organization's modules, which is what rolling a
    /// module forward to a new implementation version amounts to.
    ModuleUpgrader = 3,
}

impl RegistryRole {
    /// Whether this role may register or remove the module of `kind` for the
    /// organization it was granted on.
    pub fn may_manage(self, kind: ModuleKind) -> bool {
        match self {
            RegistryRole::Owner | RegistryRole::ModuleUpgrader => true,
            RegistryRole::PolicyManager => matches!(kind, ModuleKind::Policy),
            RegistryRole::TreasuryOperator => matches!(
                kind,
                ModuleKind::Treasury | ModuleKind::Budget | ModuleKind::Escrow
            ),
        }
    }
}

/// Key for a single version lookup in the global upgrade map.
///
/// Mirrors [`ModuleId`] for the module-address map. Used by
/// [`RegistryContract::get_versions_batch`] so a batch can carry several
/// `(kind, version)` pairs in one invocation while preserving order and
/// duplicates, just as the module batch does. Keeps the lookup surface
/// uniform across both maps.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionId {
    pub kind: ModuleKind,
    pub version: u32,
}

// ---------------------------------------------------------------------------
// Upgrade-map lookup helpers — cached, minimal ledger access.
// ---------------------------------------------------------------------------
/// Per-invocation cache for the global version upgrade map.
///
/// Persistent storage reads dominate gas. When a caller resolves many versions
/// (e.g. a batch verification or upgrade-path walk) the same
/// `(kind, version)` is often requested repeatedly. Re-reading it would pay
/// the ledger cost each time. The cache keeps the first result — including
/// `None` for a missing key — and serves duplicates by a linear scan over an
/// in-memory `Vec` bounded by `MAX_REGISTRY_BATCH`, so only comparisons are
/// paid after the first hit.
///
/// Mirrors `VelocityGate` in the wallet contract and `RuleEvaluationContext`
/// in the policy contract: reuse a ledger record within one invocation
/// rather than re-reading it.
struct VersionLookupCache {
    env: Env,
    entries: Vec<(ModuleKind, u32, Option<VersionRecord>)>,
}

impl VersionLookupCache {
    fn new(env: &Env) -> Self {
        Self {
            env: env.clone(),
            entries: Vec::new(env),
        }
    }

    /// Return the cached record for `(kind, version)`, loading it once on a miss
    /// and extending TTL only when the record exists and only once per distinct
    /// key in this invocation (matching `get_version` policy).
    fn get(&mut self, kind: ModuleKind, version: u32) -> Option<VersionRecord> {
        for i in 0..self.entries.len() {
            let (k, v, rec) = self.entries.get(i).unwrap();
            if k == kind && v == version {
                return rec.clone();
            }
        }
        let rec = RegistryContract::read_version(&self.env, kind, version);
        self.entries.push_back((kind, version, rec.clone()));
        rec
    }
}

#[contract]
pub struct RegistryContract;

/// The WASM hash a version is bound to, or the fact that it is not bound to
/// one.
///
/// Modelled as a sum type rather than an `Option` because `#[contracttype]`
/// cannot encode `Option<BytesN<32>>` — the SDK's `Option` conversion needs an
/// infallible `From<&T> for ScVal`, and `BytesN` only offers a fallible
/// `TryFrom`. The distinction is also worth making explicit on-chain: "bound to
/// this hash" and "published before hashes were bound" are different states,
/// not the presence or absence of a field.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundHash {
    /// Bound to this hash, which `get_version_wasm` reports and `verify_version`
    /// requires to match.
    Bound(BytesN<32>),
    /// Published before hashes were bound, so there is no hash to report or
    /// match — exactly the position such a version occupied when the hash lived
    /// in a separate entry that was simply absent.
    Unbound,
}

/// A registered implementation version: the address it resolves to together
/// with the WASM hash that address is bound to.
///
/// `Version` (address) and `VersionWasm` (hash) used to be two persistent
/// entries per version. Folding them into one record halves the entries a
/// populated registry holds for the upgrade map, removes one write from every
/// [`RegistryContract::register_version`], and lets
/// [`RegistryContract::verify_version`] answer from a single read where it
/// previously needed two.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRecord {
    /// The implementation this version resolves to.
    pub address: Address,
    /// The hash this version is bound to, if any.
    pub hash: BoundHash,
}

/// A validated upgrade: where a module is now and where [`RegistryContract::upgrade_module`]
/// would take it.
///
/// Internal, so it is deliberately not a `#[contracttype]`: it never crosses the
/// contract boundary. The entrypoints return the version number and the address
/// instead, which is all a caller — or the event log — needs.
struct UpgradePlan {
    /// The version the module runs today, or `0` when it was registered by
    /// address and has never been upgraded.
    from_version: u32,
    /// The version being moved onto.
    to_version: u32,
    /// The contract that version resolves to.
    address: Address,
    /// The approved WASM hash that contract is bound to.
    hash: BytesN<32>,
}

/// A validated upgrade of the registry's *own* code: the published version it
/// runs today, the published version it would move to, and the hash that names
/// the target.
///
/// The self-upgrade is expressed in versions rather than in a raw address and
/// hash for the same reason [`UpgradePlan`] resolves a module's target from the
/// version record: the hash a caller asks for is only meaningful once it has
/// been found in the map, and finding it is what establishes which version the
/// caller is really asking for. Internal, so it never crosses the boundary —
/// the entrypoints report the version number.
struct RegistryUpgradePlan {
    /// The published version the contract runs today, or `0` when it predates
    /// this key.
    from_version: u32,
    /// The published version being moved onto.
    to_version: u32,
    /// The approved WASM hash that version is bound to.
    wasm_hash: BytesN<32>,
}

// ---------------------------------------------------------------------------
// Administration & registration (inherent surface).
// ---------------------------------------------------------------------------
#[contractimpl]
impl RegistryContract {
    /// Initialize the registry with its administrator. Callable once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        let mut admins = Vec::new(&env);
        admins.push_back(admin.clone());
        env.storage().instance().set(&DataKey::Admins, &admins);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("init")), admin);
        Ok(())
    }

    /// Register an organization and its owner. Admin-gated.
    pub fn register_org(
        env: Env,
        caller: Address,
        org: String,
        owner: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        Self::require_admin(&env, &caller)?;
        let key = DataKey::Org(org.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &owner);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("org"), symbol_short!("register"), org.clone()),
            owner,
        );
        Ok(())
    }

    /// Transfer ownership of an organization. Only the current owner or the
    /// admin may reassign it.
    pub fn set_org_owner(
        env: Env,
        caller: Address,
        org: String,
        new_owner: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        let key = DataKey::Org(org.clone());
        let current: Address = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        if caller != current && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        env.storage().persistent().set(&key, &new_owner);
        Self::bump(&env, &key);
        astroid_shared::events::publish(
            &env,
            ContractEvent::OrgOwnerChanged {
                org: org.clone(),
                new_owner: new_owner.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("org"), symbol_short!("owner"), org.clone()),
            new_owner,
        );
        Ok(())
    }

    /// Register (or update) a module address for an organization. Callable by
    /// the protocol admin, the organization owner, or an account holding a
    /// delegated [`RegistryRole`] that reaches this [`ModuleKind`].
    ///
    /// The organization must already exist ([`Error::NotFound`] otherwise,
    /// whoever the caller is): all three of those permissions are defined
    /// against a recorded owner, so a registration for an organization without
    /// one would be a routing record no party is accountable for. The caller's
    /// signature is required and the permission is checked before the address is
    /// stored.
    ///
    /// The address is taken from the caller and is not otherwise vetted — this
    /// is the organization routing its own module, behind the same permission
    /// gate as always. It resets the module's version pin, because the recorded
    /// upgrade path then describes code the module no longer runs. Code that
    /// must be vetted is registered with [`Self::register_version`] and moved
    /// onto with [`Self::upgrade_module`], which never take an address.
    pub fn register_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &address);
        Self::bump(&env, &key);
        // A (re)registration points at a fresh implementation, so any prior
        // deprecation flag must not carry over and block the new address, and
        // the module's version pin starts over: the recorded upgrade path
        // describes code this module is no longer running.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
        Self::clear_module_version(&env, &org, kind);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpdated {
                org: org.clone(),
                kind,
                address: address.clone(),
            },
        );
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("register"),
                org.clone(),
                kind,
            ),
            address,
        );
        Ok(())
    }

    /// Mark a registered module as deprecated. Admin-gated. Once flagged,
    /// [`Self::lookup`] rejects new interactions with [`Error::ModuleDeprecated`]
    /// while the raw address remains readable through [`Self::get_module_address`]
    /// so legacy migrations can still reach the old implementation.
    pub fn deprecate_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&mkey) {
            return Err(Error::NotFound);
        }
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        env.storage().persistent().set(&dkey, &true);
        Self::bump(&env, &dkey);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("deprecate")),
            (org, kind),
        );
        Ok(())
    }

    /// Clear a module's deprecation flag, restoring normal routing. Admin-gated.
    pub fn reactivate_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&mkey) {
            return Err(Error::NotFound);
        }
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        env.storage().persistent().set(&dkey, &false);
        Self::bump(&env, &dkey);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("restore")),
            (org, kind),
        );
        Ok(())
    }

    /// Read a module's deprecation status (false when never flagged).
    pub fn is_module_deprecated(env: Env, org: String, kind: ModuleKind) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ModuleDeprecated(org, kind))
            .unwrap_or(false)
    }

    /// Read a registered module address bypassing the deprecation guard.
    /// Intended for legacy migrations and admin tooling that must still reach a
    /// deprecated implementation.
    pub fn get_module_address(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Module(org, kind))
            .ok_or(Error::NotFound)
    }

    /// Remove a module registration. Same gate as `register_module`: admin, org
    /// owner, or a delegated role that reaches this [`ModuleKind`].
    pub fn remove_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let key = DataKey::Module(org.clone(), kind);
        ensure!(env.storage().persistent().has(&key), Error::NotFound);
        env.storage().persistent().remove(&key);
        // Drop the deprecation flag together with the record so a later
        // re-registration starts clean and lookups report NotFound, not
        // ModuleDeprecated, for a removed module. The version pin goes with it:
        // the removed module's upgrade path is history, and keeping it would
        // make the re-registered module refuse versions it never ran.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
        Self::clear_module_version(&env, &org, kind);
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("remove"),
                org.clone(),
                kind,
            ),
            (),
        );
        Ok(())
    }

    /// Delegate `role` over `org` to `account`, replacing any role it already
    /// held. Only the recorded organization owner or the protocol admin may
    /// grant, so a delegated role can never be used to widen its own reach or
    /// to mint further delegations.
    ///
    /// Granting to the org owner is refused: the owner already reaches every
    /// module kind, so the record would be redundant and could only mislead
    /// anyone reading the delegation list.
    pub fn grant_role(
        env: Env,
        caller: Address,
        org: String,
        account: Address,
        role: RegistryRole,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        let owner = Self::require_root_owner(&env, &caller, &org)?;
        if account == owner {
            return Err(Error::InvalidInput);
        }
        let key = DataKey::OrgRole(org.clone(), account.clone());
        env.storage().persistent().set(&key, &role);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("granted")),
            (org, account, role),
        );
        Ok(())
    }

    /// Revoke whatever role `account` holds over `org`. Only the recorded
    /// organization owner or the protocol admin may revoke.
    ///
    /// Fails with [`Error::NotFound`] when the account holds no delegated role,
    /// so a revocation is never silently a no-op — an owner who believes they
    /// have withdrawn access has actually withdrawn it.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        org: String,
        account: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        Self::require_root_owner(&env, &caller, &org)?;
        let key = DataKey::OrgRole(org.clone(), account.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("revoked")),
            (org, account),
        );
        Ok(())
    }

    /// Read the role `account` holds over `org`, or `None` if it holds none.
    ///
    /// The org owner is reported as [`RegistryRole::Owner`] even though no
    /// record is stored for them, so callers see the effective permission
    /// rather than a storage detail.
    pub fn get_role(env: Env, org: String, account: Address) -> Option<RegistryRole> {
        Self::effective_role(&env, &org, &account)
    }

    /// Whether `account` may register or remove the `kind` module for `org` —
    /// the same question the entrypoint guard asks, exposed for off-chain use.
    pub fn can_manage_module(env: Env, org: String, account: Address, kind: ModuleKind) -> bool {
        if Self::is_admin(&env, &account) {
            return true;
        }
        Self::effective_role(&env, &org, &account)
            .map(|role| role.may_manage(kind))
            .unwrap_or(false)
    }

    /// Record a contract implementation for a `(kind, version)` pair, bound to
    /// the WASM hash it runs, and advance the latest-version pointer if newer.
    /// This is what powers the version-lookup upgrade strategy.
    ///
    /// Checks, in order: the registry is not frozen ([`Error::RegistryFrozen`]);
    /// `caller` is the protocol admin and signed ([`Error::Unauthorized`]);
    /// `version` is non-zero ([`Error::InvalidInput`]); the pair is not already
    /// registered ([`Error::AlreadyExists`]); `wasm_hash` is approved for `kind`
    /// via [`Self::add_approved_wasm`] ([`Error::Unauthorized`], the same code
    /// the upgrade gate reports for unapproved code). Nothing is written unless
    /// every check passes.
    ///
    /// Version records are immutable: a published version can never be
    /// repointed at different code, so a consumer pinned to it keeps getting
    /// what it pinned. Rolling forward means registering a new version.
    pub fn register_version(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        version: u32,
        address: Address,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        ensure!(version != 0, Error::InvalidInput);
        // A pair is taken if either layout already holds it. The common case is
        // a single existence check; the legacy key is only consulted when the
        // consolidated one is free, so a fresh registration still pays one read.
        ensure!(
            !env.storage()
                .persistent()
                .has(&DataKey::VersionRecord(kind, version))
                && !env
                    .storage()
                    .persistent()
                    .has(&DataKey::Version(kind, version)),
            Error::AlreadyExists
        );
        ensure!(
            Self::is_wasm_approved(env.clone(), kind, wasm_hash.clone()),
            Error::Unauthorized
        );
        // One write for the whole record, where the address and the hash used to
        // be two separate entries and two writes.
        let vkey = DataKey::VersionRecord(kind, version);
        env.storage().persistent().set(
            &vkey,
            &VersionRecord {
                address: address.clone(),
                hash: BoundHash::Bound(wasm_hash.clone()),
            },
        );
        Self::bump(&env, &vkey);

        let lkey = DataKey::LatestVersion(kind);
        let latest: u32 = env.storage().persistent().get(&lkey).unwrap_or(0);
        if version > latest {
            env.storage().persistent().set(&lkey, &version);
            Self::bump(&env, &lkey);
        }
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryVersionRegistered {
                kind,
                version,
                address: address.clone(),
                wasm_hash,
            },
        );
        env.events().publish(
            (
                symbol_short!("version"),
                symbol_short!("register"),
                kind,
                version,
            ),
            address,
        );
        Ok(())
    }

    // --- Version upgrade validation (Issue #304) ---

    /// Propose a version upgrade for a module kind: record a pending
    /// `(version, wasm_hash, address)` triple that a protocol admin can later
    /// commit ([`Self::commit_upgrade`]) or reject
    /// ([`Self::reject_upgrade`]).
    ///
    /// Validation performed:
    /// - `caller` must be the protocol admin, the recorded owner of `org`, or
    ///   an account holding a delegated [`RegistryRole::ModuleUpgrader`] over
    ///   `org` — proposals are exactly the act of rolling a module forward, so
    ///   the module-management gate is the right one.
    /// - the registry must not be frozen and `org` must be registered.
    /// - `version` must be non-zero and strictly greater than the latest
    ///   registered version for the kind, so a proposal can never be a
    ///   downgrade (downgrade-attack prevention).
    /// - `wasm_hash` must pass [`require_valid_wasm_hash`] and must not already
    ///   be approved for the kind (a re-proposal of deployed bytecode is
    ///   meaningless and usually a mistake — Issue #300's identical-WASM edge
    ///   case).
    /// - the kind must have no pending proposal ([`Error::InvalidState`]),
    ///   so the upgrade path stays unambiguous.
    ///
    /// On success the proposal is stored, `UpgradeProposed` is emitted (both
    /// the canonical and the tuple-topic form) and the action is appended to
    /// the immutable upgrade audit log ([`Self::get_upgrade_history`]). A
    /// refused proposal reverts atomically — Soroban rolls back every storage
    /// write and event of a failed invocation — so only successful lifecycle
    /// actions are ever recorded; the refusal itself remains visible off-chain
    /// as a reverted transaction.
    pub fn propose_upgrade(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        version: u32,
        wasm_hash: BytesN<32>,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        caller.require_auth();
        // Authorization: org owners and delegated module upgraders may propose;
        // everyone else — including holders of unrelated delegated roles — is
        // rejected with the canonical Unauthorized. An unknown org is reported
        // as NotFound so callers can tell a typo from a permission failure.
        if !Self::is_admin(&env, &caller) {
            match Self::effective_role(&env, &org, &caller) {
                Some(RegistryRole::ModuleUpgrader) | Some(RegistryRole::Owner) => {}
                _ => {
                    if !env.storage().persistent().has(&DataKey::Org(org.clone())) {
                        return Err(Error::NotFound);
                    }
                    return Err(Error::Unauthorized);
                }
            }
        }
        // Input validation, including the identical-WASM edge case from
        // Issue #300: re-proposing bytecode that is already approved for the
        // kind fails rather than laundering a no-op through the flow.
        ensure!(version != 0, Error::InvalidInput);
        require_valid_wasm_hash(&env, &wasm_hash)?;

        // Downgrade protection: strictly newer versions only.
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LatestVersion(kind))
            .unwrap_or(0);
        ensure!(version > latest, Error::InvalidState);

        // One open proposal per kind keeps the upgrade path unambiguous.
        let pkey = DataKey::UpgradeProposal(kind);
        ensure!(!env.storage().persistent().has(&pkey), Error::InvalidState);

        // The hash must not already be approved for the kind: proposals exist
        // to introduce new bytecode, not to re-commit something deployed.
        ensure!(
            !env.storage()
                .persistent()
                .get::<_, bool>(&DataKey::ApprovedWasm(kind, wasm_hash.clone()))
                .unwrap_or(false),
            Error::InvalidInput
        );

        let proposal = UpgradeProposal {
            version,
            wasm_hash: wasm_hash.clone(),
            address: address.clone(),
            org: org.clone(),
            proposer: caller.clone(),
            expires_at: env.ledger().timestamp() + UPGRADE_PROPOSAL_EXPIRY,
        };
        env.storage().persistent().set(&pkey, &proposal);
        Self::bump(&env, &pkey);

        let audit_log = UpgradeAudit {
            kind,
            version,
            wasm_hash: wasm_hash.clone(),
            org: org.clone(),
            actor: caller,
            recorded_at: env.ledger().timestamp(),
        };
        Self::append_audit(&env, UpgradeAction::Proposed, &audit_log);
        events::upgrade_proposed(&env, kind, version, &wasm_hash);
        events::publish(&env, ContractEvent::UpgradeProposed { audit: audit_log });
        Ok(())
    }

    /// Commit a pending upgrade proposal: record the proposed address in the
    /// version table, approve the proposed Wasm hash for the kind, clear the
    /// pending record and emit `UpgradeCommitted`.
    ///
    /// Committing is the higher-bar side of the flow and is admin-gated. All of
    /// the proposal's validation is re-checked at commit time so nothing that
    /// became invalid while the proposal was pending can slip through:
    /// - the proposal must exist for the kind ([`Error::NotFound`]) and must
    ///   not have expired (a matured proposal stays refuseable forever);
    /// - `version` must still be strictly greater than the latest registered
    ///   version (nothing was committed in the meantime);
    /// - `wasm_hash` must still be well-formed.
    ///
    /// A successful commit appends `Committed` to the audit log and emits
    /// `UpgradeCommitted` (canonical and tuple-topic form); any refusal reverts
    /// atomically, so refused commits never touch the trail.
    pub fn commit_upgrade(
        env: Env,
        caller: Address,
        kind: ModuleKind,
    ) -> Result<(u32, Address), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;

        let pkey = DataKey::UpgradeProposal(kind);
        let proposal: UpgradeProposal = env
            .storage()
            .persistent()
            .get(&pkey)
            .ok_or(Error::NotFound)?;

        // Expiry: a matured proposal is dropped once and for all — committing
        // it is refused forever after (the check re-runs on every attempt).
        if env.ledger().timestamp() > proposal.expires_at {
            return Err(Error::NotFound);
        }

        // Re-validate everything the proposal asserted at propose time; the
        // world may have moved underneath it while it was pending.
        require_valid_wasm_hash(&env, &proposal.wasm_hash)?;
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LatestVersion(kind))
            .unwrap_or(0);
        ensure!(proposal.version > latest, Error::InvalidState);

        // Commit: version table + wasm approval, then clear the pending record.
        let vkey = DataKey::Version(kind, proposal.version);
        env.storage().persistent().set(&vkey, &proposal.address);
        Self::bump(&env, &vkey);
        let lkey = DataKey::LatestVersion(kind);
        env.storage().persistent().set(&lkey, &proposal.version);
        Self::bump(&env, &lkey);
        let akey = DataKey::ApprovedWasm(kind, proposal.wasm_hash.clone());
        env.storage().persistent().set(&akey, &true);
        Self::bump(&env, &akey);
        env.storage().persistent().remove(&pkey);

        let version = proposal.version;
        let address = proposal.address.clone();
        let wasm_hash = proposal.wasm_hash.clone();

        let audit_log = UpgradeAudit {
            kind,
            version,
            wasm_hash: wasm_hash.clone(),
            org: proposal.org,
            actor: caller,
            recorded_at: env.ledger().timestamp(),
        };
        Self::append_audit(&env, UpgradeAction::Committed, &audit_log);
        events::upgrade_committed(&env, kind, version, &wasm_hash, &address);
        events::publish(
            &env,
            ContractEvent::UpgradeCommitted {
                audit: audit_log,
                address: address.clone(),
            },
        );
        // Same payload as the canonical event, keeping the legacy
        // ("version", "register") topic consumers working.
        env.events().publish(
            (
                symbol_short!("version"),
                symbol_short!("register"),
                kind,
                version,
            ),
            address.clone(),
        );
        Ok((version, address))
    }

    /// Reject (or withdraw) a pending upgrade proposal: clear the pending
    /// record and emit `UpgradeRejected`.
    ///
    /// The proposer may withdraw their own proposal; the protocol admin may
    /// reject any proposal. An org owner may also reject a proposal targeting
    /// their organization's module kind, so an owner can always stop an
    /// upgrade they no longer want even if they did not propose it. Deleting a
    /// non-existent proposal fails with [`Error::NotFound`], so a rejection is
    /// never silently a no-op.
    ///
    /// A successful rejection appends `Rejected` to the audit log and emits
    /// `UpgradeRejected` (canonical and tuple-topic form); any refusal reverts
    /// atomically, so refused rejections never touch the trail.
    pub fn reject_upgrade(env: Env, caller: Address, kind: ModuleKind) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();

        let pkey = DataKey::UpgradeProposal(kind);
        let proposal: UpgradeProposal = env
            .storage()
            .persistent()
            .get(&pkey)
            .ok_or(Error::NotFound)?;

        let authorized = Self::is_admin(&env, &caller)
            || proposal.proposer == caller
            || env
                .storage()
                .persistent()
                .get::<_, Address>(&DataKey::Org(proposal.org.clone()))
                .map(|owner| owner == caller)
                .unwrap_or(false);
        ensure!(authorized, Error::Unauthorized);

        env.storage().persistent().remove(&pkey);
        let audit_log = UpgradeAudit {
            kind,
            version: proposal.version,
            wasm_hash: proposal.wasm_hash.clone(),
            org: proposal.org,
            actor: caller,
            recorded_at: env.ledger().timestamp(),
        };
        Self::append_audit(&env, UpgradeAction::Rejected, &audit_log);
        events::upgrade_rejected(&env, kind, proposal.version, &proposal.wasm_hash);
        events::publish(&env, ContractEvent::UpgradeRejected { audit: audit_log });
        Ok(())
    }

    /// The immutable historical upgrade log (Issue #300): every successful
    /// propose, commit and reject, most recent entry first. Records are never
    /// edited or removed; the log is a ring buffer capped at
    /// [`MAX_UPGRADE_AUDIT_ENTRIES`] entries.
    pub fn get_upgrade_history(env: Env) -> Vec<UpgradeAuditRecord> {
        env.storage()
            .instance()
            .get(&DataKey::UpgradeAuditLog)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Number of upgrade audit entries currently retained.
    pub fn get_upgrade_history_len(env: Env) -> u32 {
        Self::upgrade_log(&env).len()
    }

    /// Read the pending upgrade proposal for a kind, if any.
    pub fn get_upgrade_proposal(env: Env, kind: ModuleKind) -> Option<UpgradeProposal> {
        Self::pending_proposal(&env, &kind)
    }

    /// Look up a specific implementation version.
    pub fn get_version(env: Env, kind: ModuleKind, version: u32) -> Result<Address, Error> {
        Ok(Self::read_version(&env, kind, version)
            .ok_or(Error::NotFound)?
            .address)
    }

    /// Read the WASM hash a registered version is bound to. Fails with
    /// [`Error::NotFound`] for an unknown `(kind, version)`, and for a version
    /// registered before hashes were bound (it has no hash to report).
    pub fn get_version_wasm(env: Env, kind: ModuleKind, version: u32) -> Result<BytesN<32>, Error> {
        match Self::read_version(&env, kind, version).map(|rec| rec.hash) {
            Some(BoundHash::Bound(hash)) => Ok(hash),
            _ => Err(Error::NotFound),
        }
    }

    /// Verify that `(kind, version)` is registered, runs exactly `wasm_hash`,
    /// and that the hash is still approved; on success return the version's
    /// address. Read-only, so a deployer or consumer can check an upgrade
    /// target before acting on it.
    ///
    /// Errors: [`Error::NotFound`] for an unknown version;
    /// [`Error::InvalidInput`] when `wasm_hash` differs from the bound hash (or
    /// the version predates hash binding and so has none to match);
    /// [`Error::Unauthorized`] when the bound hash has since been removed from
    /// the approved list.
    pub fn verify_version(
        env: Env,
        kind: ModuleKind,
        version: u32,
        wasm_hash: BytesN<32>,
    ) -> Result<Address, Error> {
        // One read for the address and its bound hash together; the split
        // layout needed a second read for the hash.
        let record = Self::read_version(&env, kind, version).ok_or(Error::NotFound)?;
        ensure!(
            matches!(record.hash, BoundHash::Bound(ref bound) if bound == &wasm_hash),
            Error::InvalidInput
        );
        ensure!(
            Self::is_wasm_approved(env, kind, wasm_hash),
            Error::Unauthorized
        );
        Ok(record.address)
    }

    /// Move `org`'s `kind` module onto the implementation registered at
    /// `target_version` for that same kind, after checking the whole upgrade
    /// path. Returns the version the module now runs.
    ///
    /// The address and the WASM hash are resolved from the version record, never
    /// taken from the caller, so there is no way to point a module at a contract
    /// the protocol admin did not publish for its kind or at code whose hash is
    /// not approved. See the crate-level "Upgrade paths" section for the full
    /// order of checks; the short version is:
    ///
    /// 1. the registry is not frozen — [`Error::RegistryFrozen`];
    /// 2. `caller` is signed and may manage this `kind` for `org` —
    ///    [`Error::Unauthorized`] (or [`Error::NotFound`] for an unknown org);
    /// 3. the module is already registered — [`Error::NotFound`];
    /// 4. `target_version` is non-zero — [`Error::InvalidInput`];
    /// 5. `target_version` is strictly newer than the module's current pin —
    ///    [`Error::CircularUpgrade`], which is what stops the path from
    ///    revisiting or reversing;
    /// 6. the target version exists for this kind — [`Error::NotFound`];
    /// 7. the target is bound to a WASM hash — [`Error::InvalidInput`] for a
    ///    version published before hashes were bound, so there is nothing to
    ///    verify;
    /// 8. that hash is still approved for this kind — [`Error::Unauthorized`]
    ///    for code that was never approved or has since been revoked;
    /// 9. the target address is a contract — [`Error::InvalidInput`], so the
    ///    module can never be routed to an account;
    /// 10. the target is not the contract the module already runs —
    ///     [`Error::CircularUpgrade`].
    ///
    /// On success the module pointer moves, the deprecation flag is cleared (the
    /// module is running a live implementation again) and the pin advances to
    /// `target_version`. Nothing is written unless every check passes, so a
    /// refusal leaves the module exactly where it was.
    ///
    /// A `0` pin (see [`Self::get_module_version`]) means the module was
    /// registered by address and has never been upgraded, so it accepts any
    /// registered version as its first step.
    pub fn upgrade_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        target_version: u32,
    ) -> Result<u32, Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let plan = Self::plan_upgrade(&env, &org, kind, target_version)?;

        // Past this line every check has passed; only writes remain.
        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &plan.address);
        Self::bump(&env, &key);
        let vkey = DataKey::ModuleVersion(org.clone(), kind);
        env.storage().persistent().set(&vkey, &plan.to_version);
        Self::bump(&env, &vkey);
        // The module runs a registered implementation again, so a deprecation
        // flag left by the implementation it just left must not keep the new
        // address unroutable.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }

        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpgraded {
                org: org.clone(),
                kind,
                from_version: plan.from_version,
                to_version: plan.to_version,
                address: plan.address.clone(),
                wasm_hash: plan.hash.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("module"), symbol_short!("upgrade")),
            (org, kind, plan.to_version),
        );
        Ok(plan.to_version)
    }

    /// Register `org`'s `kind` module onto a published implementation version,
    /// resolving the address from the registry instead of taking one from the
    /// caller.
    ///
    /// [`Self::register_module`] accepts whatever address the caller names, so
    /// that path can point a module at code the registry never published or
    /// approved. This entrypoint closes the gap for versioned deployments: both
    /// the address and the WASM hash come from the immutable `(kind, version)`
    /// record, and the module's version pin advances to `version`.
    ///
    /// The validations are exactly [`Self::upgrade_module`]'s (see the
    /// crate-level "Upgrade paths" section), which is what makes the upgrade
    /// path monotonic even when it is driven through registration:
    ///
    /// - `version` is non-zero and strictly newer than the module's existing pin
    ///   — [`Error::CircularUpgrade`] for a version the module has already left,
    ///   or for the one it already runs;
    /// - the target version exists for this `kind` — [`Error::NotFound`];
    /// - the target is bound to a WASM hash — [`Error::InvalidInput`];
    /// - that hash is still approved for this `kind` — [`Error::Unauthorized`];
    /// - the resolved address is a contract — [`Error::InvalidInput`].
    ///
    /// Registering a module that was never registered is legal and starts its
    /// path; registering over an existing one is a validated repoint, and any
    /// deprecation flag is cleared because the module runs a live implementation
    /// again. On success the pointer, the pin and the events match what
    /// [`Self::upgrade_module`] would have produced for the same target, so an
    /// indexer sees one upgrade path whichever entrypoint drove it. Returns the
    /// version the module now runs.
    pub fn register_module_version(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        version: u32,
    ) -> Result<u32, Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        // Registration may create the record or replace one; either way the
        // version path is validated against the current pointer when there is
        // one, so a repoint can never walk backwards.
        let current: Option<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Module(org.clone(), kind));
        let existed = current.is_some();
        let plan = Self::resolve_upgrade_target(&env, &org, kind, version, current)?;

        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &plan.address);
        Self::bump(&env, &key);
        let vkey = DataKey::ModuleVersion(org.clone(), kind);
        env.storage().persistent().set(&vkey, &plan.to_version);
        Self::bump(&env, &vkey);
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }

        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpdated {
                org: org.clone(),
                kind,
                address: plan.address.clone(),
            },
        );
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("register"),
                org.clone(),
                kind,
            ),
            plan.address.clone(),
        );
        // A repoint moves an existing module, so it is reported as an upgrade
        // too: consumers that only track `RegistryModuleUpgraded` see the same
        // history as they would have through `upgrade_module`.
        if existed {
            astroid_shared::events::publish(
                &env,
                ContractEvent::RegistryModuleUpgraded {
                    org: org.clone(),
                    kind,
                    from_version: plan.from_version,
                    to_version: plan.to_version,
                    address: plan.address.clone(),
                    wasm_hash: plan.hash.clone(),
                },
            );
            env.events().publish(
                (symbol_short!("module"), symbol_short!("upgrade")),
                (org, kind, plan.to_version),
            );
        }
        Ok(plan.to_version)
    }

    /// Run every check [`Self::upgrade_module`] would run and return the address
    /// the module would be moved to, writing nothing.
    ///
    /// A keeper, a deployment script or a test can confirm that a target is
    /// reachable — version published, hash approved, path not circular — before
    /// asking for the migration. The checks, and the order they fire in, are
    /// identical to the write path's, so a successful validation predicts a
    /// successful upgrade (and a refusal carries the same code the upgrade
    /// would have reported).
    ///
    /// Read-only: it moves no pointer and writes no pin, and it needs no auth.
    /// The one ledger write it may cause is the version record's TTL extension,
    /// which any read of that record already pays for. It does consult the
    /// freeze flag, like [`Self::lookup`], so a pre-flight run does not approve
    /// an upgrade the registry would refuse to record.
    pub fn validate_upgrade(
        env: Env,
        org: String,
        kind: ModuleKind,
        target_version: u32,
    ) -> Result<Address, Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        Ok(Self::plan_upgrade(&env, &org, kind, target_version)?.address)
    }

    /// The version `org`'s `kind` module is currently pinned to.
    ///
    /// `0` means the module is registered by address and has never been moved by
    /// [`Self::upgrade_module`] — which is the state of every module registered
    /// before that entrypoint existed, so those need no migration to take part in
    /// validated upgrades. [`Error::NotFound`] is reserved for "no such module",
    /// keeping the two apart: `Ok(0)` is a module with an upgrade path ahead of
    /// it, `NotFound` is not a module at all.
    pub fn get_module_version(env: Env, org: String, kind: ModuleKind) -> Result<u32, Error> {
        let key = DataKey::Module(org.clone(), kind);
        ensure!(env.storage().persistent().has(&key), Error::NotFound);
        Ok(env
            .storage()
            .persistent()
            .get(&DataKey::ModuleVersion(org, kind))
            .unwrap_or(0))
    }

    /// The published `Organization` version whose code this registry is
    /// currently running.
    ///
    /// `0` means the contract predates the key — it was deployed from code that
    /// was never recorded as an `Organization` version — and stands at the start
    /// of its own upgrade path, exactly as an unpinned module does. Unlike
    /// [`Self::get_module_version`] this cannot fail: the registry is always
    /// running something, and the answer for code published before this key
    /// existed is the same answer it gives for a module it has never upgraded.
    pub fn get_registry_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::RegistryVersion)
            .unwrap_or(0)
    }

    /// Run every check [`Self::upgrade`] would run against the version upgrade
    /// map and return the version this registry would move to, writing nothing.
    ///
    /// The registry is its own upgrade map, so this is the dry run a deployer
    /// wants before asking for the code swap: it answers whether `wasm_hash` is
    /// code the registry has actually published for [`ModuleKind::Organization`],
    /// and whether the version carrying it is still ahead of the one running.
    /// The checks, and the codes they report, are the write path's, so a
    /// successful validation predicts a successful upgrade and a refusal carries
    /// the code the upgrade would have reported.
    ///
    /// Read-only and auth-free, like [`Self::validate_upgrade`]: it moves no
    /// code, records no version and needs no signature, and the only ledger
    /// writes it can cause are the TTL extensions any read of a version record
    /// already pays for. It does not stand in for the authorization gate —
    /// whether the caller is the recorded upgrade admin and the hash is still
    /// approved is settled by the signature [`Self::upgrade`] collects, not here.
    ///
    /// Not gated on the freeze flag, and neither is [`Self::upgrade`]: the freeze
    /// stops org-scoped writes, and a registry that could not replace its own
    /// code during an incident would be the one contract nobody could repair.
    pub fn validate_registry_upgrade(env: Env, wasm_hash: BytesN<32>) -> Result<u32, Error> {
        Ok(Self::plan_registry_upgrade(&env, &wasm_hash)?.to_version)
    }

    /// Look up the latest implementation address for a kind.
    pub fn get_latest(env: Env, kind: ModuleKind) -> Result<Address, Error> {
        let key = DataKey::LatestVersion(kind);
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Self::get_version(env, kind, latest)
    }

    /// Batch counterpart of [`Self::get_version`]: resolve up to
    /// [`MAX_REGISTRY_BATCH`] version addresses in one invocation.
    ///
    /// - `result[i]` answers `ids[i]`; length and order are preserved and
    ///   duplicate ids are answered at every position.
    /// - An unregistered id yields `None` instead of failing the batch, so one
    ///   missing version does not hide the others.
    /// - A mix of registered and missing ids is handled per entry.
    /// - An empty `ids` returns an empty list.
    ///
    /// Errors: [`Error::InvalidInput`] when more than [`MAX_REGISTRY_BATCH`] ids
    /// are requested (checked before any storage is read). Read-only: no auth
    /// is required and the frozen flag is not consulted, matching
    /// [`Self::get_version`].
    ///
    /// Gas optimization: a per-invocation [`VersionLookupCache`] keeps the first
    /// ledger read for each distinct `(kind, version)` — including `None` for a
    /// missing key — and serves duplicates from an in-memory `Vec` bounded by
    /// [`MAX_REGISTRY_BATCH`]. A batch with duplicates therefore pays one
    /// persistent read and one TTL bump per distinct key, not per entry, while
    /// preserving order and duplicates exactly like [`Self::get_modules_batch`].
    pub fn get_versions_batch(
        env: Env,
        ids: Vec<VersionId>,
    ) -> Result<Vec<Option<Address>>, Error> {
        ensure!(ids.len() <= MAX_REGISTRY_BATCH, Error::InvalidInput);
        let mut cache = VersionLookupCache::new(&env);
        let mut results = Vec::new(&env);
        for vid in ids.iter() {
            results.push_back(cache.get(vid.kind, vid.version).map(|rec| rec.address));
        }
        Ok(results)
    }

    /// Read the recorded owner of an organization.
    pub fn get_org_owner(env: Env, org: String) -> Result<Address, Error> {
        let key = DataKey::Org(org);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(val)
    }

    /// Read the current admin.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Rotate the admin. Only an authorized admin or multisig may do this.
    /// Replaces the old primary admin with `new_admin` in the multi-admin set.
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let old_admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        let admins: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| Vec::new(&env));
        let mut updated_admins = Vec::new(&env);
        for a in admins.iter() {
            if let Some(ref old) = old_admin {
                if &a == old {
                    continue;
                }
            }
            if a != new_admin {
                updated_admins.push_back(a);
            }
        }
        updated_admins.push_back(new_admin.clone());
        env.storage()
            .instance()
            .set(&DataKey::Admins, &updated_admins);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events().publish(
            (symbol_short!("registry"), symbol_short!("setadmin")),
            new_admin,
        );
        Ok(())
    }

    /// Add an authorized administrator. Admin or multisig gated.
    pub fn add_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let mut admins: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| {
                let mut v = Vec::new(&env);
                if let Some(admin) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
                    v.push_back(admin);
                }
                v
            });
        ensure!(admins.len() < MAX_APPROVERS, Error::InvalidInput);
        ensure!(!admins.contains(&new_admin), Error::AlreadyExists);
        admins.push_back(new_admin.clone());
        env.storage().instance().set(&DataKey::Admins, &admins);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events()
            .publish((symbol_short!("admin"), symbol_short!("added")), new_admin);
        Ok(())
    }

    /// Remove an authorized administrator. Admin or multisig gated.
    /// At least one admin must remain in the authorized admin set.
    pub fn remove_admin(env: Env, caller: Address, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let admins: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| {
                let mut v = Vec::new(&env);
                if let Some(a) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
                    v.push_back(a);
                }
                v
            });
        ensure!(admins.contains(&admin), Error::NotFound);
        ensure!(admins.len() > 1, Error::InvalidInput);

        let mut new_admins = Vec::new(&env);
        for a in admins.iter() {
            if a != admin {
                new_admins.push_back(a);
            }
        }
        env.storage().instance().set(&DataKey::Admins, &new_admins);

        // If the primary admin was removed, rotate DataKey::Admin to the first remaining admin.
        if let Some(primary) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
            if primary == admin {
                let next_primary = new_admins.get(0).unwrap();
                env.storage().instance().set(&DataKey::Admin, &next_primary);
            }
        }

        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events()
            .publish((symbol_short!("admin"), symbol_short!("removed")), admin);
        Ok(())
    }

    /// Return all authorized multi-admin principals.
    pub fn get_admins(env: Env) -> Result<Vec<Address>, Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        let admins: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Admins)
            .unwrap_or_else(|| {
                let mut v = Vec::new(&env);
                if let Some(a) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
                    v.push_back(a);
                }
                v
            });
        Ok(admins)
    }

    /// Configure or rotate the designated multisig governance contract.
    pub fn set_multisig(env: Env, caller: Address, multisig: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Multisig, &multisig);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("multisig")),
            multisig,
        );
        Ok(())
    }

    /// Read the designated multisig governance contract, if configured.
    pub fn get_multisig(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Multisig)
    }

    /// Remove the designated multisig governance contract.
    pub fn remove_multisig(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if !env.storage().instance().has(&DataKey::Multisig) {
            return Err(Error::NotFound);
        }
        env.storage().instance().remove(&DataKey::Multisig);
        Ok(())
    }

    /// Check whether an address is an authorized protocol administrator or the
    /// designated multisig governance contract.
    pub fn is_authorized_admin(env: Env, who: Address) -> bool {
        Self::is_admin(&env, &who)
    }

    /// Emergency freeze - only registered org owners can freeze.
    pub fn freeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        ensure!(
            owner == caller || Self::is_admin(&env, &caller),
            Error::Unauthorized
        );
        env.storage().instance().set(&DataKey::Frozen, &true);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: true,
            },
        );
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("frozen")), org);
        Ok(())
    }

    /// Unfreeze - only registered org owners can unfreeze (works even when frozen).
    pub fn unfreeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        // Bypass frozen check - unfreeze must work even when frozen
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        ensure!(
            owner == caller || Self::is_admin(&env, &caller),
            Error::Unauthorized
        );
        env.storage().instance().set(&DataKey::Frozen, &false);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: false,
            },
        );
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("unfrozen")), org);
        Ok(())
    }

    /// Record an approved WASM hash for a specific module kind.
    ///
    /// The hash must be well-formed ([`require_valid_wasm_hash`]) and must not
    /// conflict with a pending upgrade proposal for the kind: while a proposal
    /// is open, an approval of a *different* hash would let the proposal be
    /// committed against bytecode the proposers never saw, so it is refused
    /// with [`Error::InvalidState`] until the proposal is committed or
    /// rejected.
    pub fn add_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        require_valid_wasm_hash(&env, &wasm_hash)?;
        if let Some(pending) = Self::pending_proposal(&env, &kind) {
            ensure!(pending.wasm_hash == wasm_hash, Error::InvalidState);
        }
        let key = DataKey::ApprovedWasm(kind, wasm_hash.clone());
        env.storage().persistent().set(&key, &true);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("approved")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Remove/deprecate a previously approved WASM hash.
    pub fn remove_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedWasm(kind, wasm_hash.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("removed")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Read-only check to see if a WASM hash is approved for a given kind.
    pub fn is_wasm_approved(env: Env, kind: ModuleKind, wasm_hash: BytesN<32>) -> bool {
        let key = DataKey::ApprovedWasm(kind, wasm_hash);
        env.storage().persistent().get(&key).unwrap_or(false)
    }

    // --- internal helpers ---

    // --- upgrade audit trail (Issue #300) ---

    /// Read the audit log (most recent entry first).
    fn upgrade_log(env: &Env) -> Vec<UpgradeAuditRecord> {
        env.storage()
            .instance()
            .get(&DataKey::UpgradeAuditLog)
            .unwrap_or_else(|| vec![env])
    }

    /// Append `record` to the immutable audit log, newest first, dropping the
    /// oldest entry once the ring buffer reaches [`MAX_UPGRADE_AUDIT_ENTRIES`].
    ///
    /// Only called on the success paths of the upgrade lifecycle; a Soroban
    /// invocation is atomic, so had the surrounding call failed this write
    /// would be rolled back along with everything else it did.
    fn append_audit(env: &Env, action: UpgradeAction, audit: &UpgradeAudit) {
        let mut log = Self::upgrade_log(env);
        log.push_front(UpgradeAuditRecord {
            action,
            audit: audit.clone(),
        });
        while log.len() > MAX_UPGRADE_AUDIT_ENTRIES {
            log.pop_back();
        }
        env.storage()
            .instance()
            .set(&DataKey::UpgradeAuditLog, &log);
    }

    /// Read the pending upgrade proposal for `kind`, if one is stored. The
    /// only consumer of the raw record besides the upgrade flow itself, so the
    /// expiry check lives at the flow's commit path rather than here.
    fn pending_proposal(env: &Env, kind: &ModuleKind) -> Option<UpgradeProposal> {
        env.storage()
            .persistent()
            .get(&DataKey::UpgradeProposal(*kind))
    }

    /// Validate the upgrade of `org`'s `kind` module to `target_version` and
    /// return everything the caller needs to carry it out. Moves nothing, so
    /// [`Self::validate_upgrade`] and [`Self::upgrade_module`] reach identical
    /// conclusions and report identical codes.
    ///
    /// The target is resolved from the immutable version record rather than from
    /// the caller's arguments, which is what makes an unverified hash
    /// unrepresentable here: there is no way to name code the registry has not
    /// published and approved for this `kind`.
    fn plan_upgrade(
        env: &Env,
        org: &String,
        kind: ModuleKind,
        target_version: u32,
    ) -> Result<UpgradePlan, Error> {
        // An upgrade moves an existing registration, so there must be one. The
        // address is read for the "already running this contract" check below,
        // which makes the extra read pay for itself.
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Module(org.clone(), kind))
            .ok_or(Error::NotFound)?;
        Self::resolve_upgrade_target(env, org, kind, target_version, Some(current))
    }

    /// The version-path checks shared by [`Self::upgrade_module`] and
    /// [`Self::register_module_version`].
    ///
    /// `current` is the address the module runs today, or `None` when the record
    /// does not exist yet (a versioned registration). Everything else — the
    /// non-zero target, the monotonic ordering against the pin, the published
    /// version record, its bound-and-approved hash and the contract-address
    /// check — is identical on both paths, so the two entrypoints can never
    /// disagree about whether a target is reachable.
    fn resolve_upgrade_target(
        env: &Env,
        org: &String,
        kind: ModuleKind,
        target_version: u32,
        current: Option<Address>,
    ) -> Result<UpgradePlan, Error> {
        // Version `0` is never a valid record (`register_version` refuses it), so
        // it can only be an uninitialized read.
        ensure!(target_version != 0, Error::InvalidInput);

        // Version ordering. The pin is a high-water mark, so this is the check
        // that makes an upgrade path acyclic: a module can never re-enter a
        // version it has already left, and never move backwards onto one. An
        // unpinned module (0) is at the start of its path, so any version is
        // forward of it.
        let from_version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ModuleVersion(org.clone(), kind))
            .unwrap_or(0);
        ensure!(target_version > from_version, Error::CircularUpgrade);

        // Existence, then integrity: the target must be a published version of
        // *this* kind, bound to code that is still approved for it.
        let record = Self::read_version(env, kind, target_version).ok_or(Error::NotFound)?;
        let hash = match record.hash {
            BoundHash::Bound(hash) => hash,
            // A version published before hashes were bound has nothing to
            // verify, so it cannot be moved onto: the point of this path is that
            // the code behind a module is known.
            BoundHash::Unbound => return Err(Error::InvalidInput),
        };
        ensure!(
            Self::is_wasm_approved(env.clone(), kind, hash.clone()),
            Error::Unauthorized
        );
        // A module must be routable, and only a contract can be called. Without
        // this, a version record naming an account would leave the module
        // permanently unroutable.
        ensure!(
            Self::is_contract_address(&record.address),
            Error::InvalidInput
        );
        // A "move" onto the contract the module already runs is the degenerate
        // cycle: it changes no code and no routing, so it is refused rather than
        // silently recorded as progress. A versioned registration of a module
        // that does not exist yet has nothing to compare against.
        if let Some(current) = current {
            ensure!(record.address != current, Error::CircularUpgrade);
        }

        Ok(UpgradePlan {
            from_version,
            to_version: target_version,
            address: record.address,
            hash,
        })
    }

    /// Validate an upgrade of the registry's *own* code to `wasm_hash` and
    /// return everything [`Self::upgrade`] needs to carry it out. Moves nothing,
    /// so [`Self::validate_registry_upgrade`] and [`Self::upgrade`] reach
    /// identical conclusions and report identical codes.
    ///
    /// This is the version upgrade map's role made load-bearing for the
    /// registry itself. `upgrade` takes a bare hash, and a hash on its own says
    /// nothing about ordering: an approved hash is approval, not progression,
    /// and an implementation that stays on the approved list long enough to be
    /// needed by an old deployment is exactly the one a downgrade would reach
    /// for. So the hash is resolved *back* to the published
    /// `Organization` version that carries it, and the registry's own
    /// high-water mark decides whether that version is a step forward.
    ///
    /// The scan runs newest-published-first and takes the *highest* version
    /// bound to the hash, which is the only reading consistent with strict
    /// monotonicity: if the same code was published as both v2 and v7, "move to
    /// that code" means v7, and a registry already on v8 is refusing a downgrade
    /// either way. Searching the whole published range — rather than stopping
    /// at the running version — is what lets a refused downgrade be reported as
    /// [`Error::CircularUpgrade`] instead of being mistaken for code the
    /// registry has never published, which is the distinction deployment tooling
    /// walks an upgrade path with.
    fn plan_registry_upgrade(
        env: &Env,
        wasm_hash: &BytesN<32>,
    ) -> Result<RegistryUpgradePlan, Error> {
        let from_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::RegistryVersion)
            .unwrap_or(0);
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LatestVersion(ModuleKind::Organization))
            .unwrap_or(0);
        // No version has ever been published for the registry's own kind, so
        // there is nothing for a hash to be resolved against.
        ensure!(latest != 0, Error::NotFound);

        // Newest first, over a window of published versions rather than over the
        // whole `1..=latest` range: see `MAX_UPGRADE_SCAN`.
        let floor = latest.saturating_sub(MAX_UPGRADE_SCAN - 1);
        let mut version = latest;
        let mut found: Option<(u32, VersionRecord)> = None;
        while version >= floor && version > 0 {
            if let Some(record) = Self::read_version(env, ModuleKind::Organization, version) {
                if matches!(&record.hash, BoundHash::Bound(bound) if bound == wasm_hash) {
                    found = Some((version, record));
                    break;
                }
            }
            version -= 1;
        }
        // Approved code that no published version carries is code the upgrade map
        // does not vouch for: a hash nobody ever released for this registry, and
        // therefore one with no version to compare against.
        let (to_version, record) = found.ok_or(Error::NotFound)?;

        // The ordering guarantee. This is the whole point: the registry's own
        // version is a high-water mark, so it can never re-enter a version it has
        // left and never move backwards onto one, no matter how long the
        // superseded code stays approved. A registry that predates the key reads
        // as `0` and so accepts any published version as its first step.
        ensure!(to_version > from_version, Error::CircularUpgrade);

        // The published record has to name a contract, not an account. A
        // `Organization` version is a deployment of this contract, and a record
        // that names an account is not one — refusing it keeps a malformed
        // record from being laundered into an accepted upgrade target.
        ensure!(
            Self::is_contract_address(&record.address),
            Error::InvalidInput
        );

        Ok(RegistryUpgradePlan {
            from_version,
            to_version,
            wasm_hash: wasm_hash.clone(),
        })
    }

    /// Whether `address` is a contract principal rather than an account.
    ///
    /// SDK 21 exposes no `is_contract`, so this reads the type byte off the
    /// address's canonical strkey encoding: `C` marks a contract ID, `G` an
    /// ed25519 account. Strkeys are always 56 characters, so anything else is
    /// treated as not-a-contract. Same check as the treasury's
    /// `is_contract_address`, kept local so the registry does not depend on a
    /// member contract.
    fn is_contract_address(address: &Address) -> bool {
        let strkey = address.to_string();
        let mut buf = [0u8; 56];
        if strkey.len() as usize != buf.len() {
            return false;
        }
        strkey.copy_into_slice(&mut buf);
        buf[0] == b'C'
    }

    /// Forget a module's version pin. Called from the two paths that replace or
    /// remove the registration itself, so a pin can never outlive the record it
    /// describes. Absent keys are left alone rather than written as `0`, keeping
    /// the entry table no larger than it needs to be.
    fn clear_module_version(env: &Env, org: &String, kind: ModuleKind) {
        let key = DataKey::ModuleVersion(org.clone(), kind);
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
        }
    }

    /// Resolve `(kind, version)` to its record, or `None` when unregistered.
    ///
    /// A single read on the current layout. Versions published before the record
    /// was consolidated stored only their address under [`DataKey::Version`], so
    /// that key is consulted second and such a version still resolves — with no
    /// bound hash, which is precisely how it behaved when the hash lived in a
    /// separate entry that was simply absent. An already-registered version
    /// therefore keeps answering every query across the layout change.
    ///
    /// The fallback is the only extra read in this function, and it costs a miss
    /// (an absent key deserializes nothing). Entries written after the
    /// consolidation never reach it.
    fn read_version(env: &Env, kind: ModuleKind, version: u32) -> Option<VersionRecord> {
        let key = DataKey::VersionRecord(kind, version);
        if let Some(record) = env.storage().persistent().get::<_, VersionRecord>(&key) {
            Self::bump(env, &key);
            return Some(record);
        }
        let legacy = DataKey::Version(kind, version);
        let address: Option<Address> = env.storage().persistent().get(&legacy);
        if address.is_some() {
            Self::bump(env, &legacy);
        }
        address.map(|address| VersionRecord {
            address,
            hash: BoundHash::Unbound,
        })
    }

    fn check_frozen(env: &Env) -> Result<(), Error> {
        ensure!(
            !env.storage()
                .instance()
                .get::<_, bool>(&DataKey::Frozen)
                .unwrap_or(false),
            Error::RegistryFrozen
        );
        Ok(())
    }

    fn is_admin(env: &Env, who: &Address) -> bool {
        if let Some(admin) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
            if &admin == who {
                return true;
            }
        }
        if let Some(admins) = env
            .storage()
            .instance()
            .get::<_, Vec<Address>>(&DataKey::Admins)
        {
            if admins.contains(who) {
                return true;
            }
        }
        if let Some(multisig) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::Multisig)
        {
            if &multisig == who {
                return true;
            }
        }
        false
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        ensure!(Self::is_admin(env, caller), Error::Unauthorized);
        Ok(())
    }

    /// Require the caller to be the *recorded* organization owner (or the
    /// protocol admin) and return that owner. Used for the root actions that
    /// are deliberately not delegable, so a delegated role can never administer
    /// roles or otherwise escalate.
    fn require_root_owner(env: &Env, caller: &Address, org: &String) -> Result<Address, Error> {
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        if &owner != caller && !Self::is_admin(env, caller) {
            return Err(Error::Unauthorized);
        }
        Ok(owner)
    }

    /// Resolve the role `account` effectively holds over `org`, treating the
    /// recorded owner as an implicit [`RegistryRole::Owner`]. Returns `None`
    /// for an unknown organization, which the callers report as
    /// [`Error::Unauthorized`] — a stranger asking about a non-existent org
    /// learns nothing either way.
    fn effective_role(env: &Env, org: &String, account: &Address) -> Option<RegistryRole> {
        let owner: Option<Address> = env.storage().persistent().get(&DataKey::Org(org.clone()));
        if owner.as_ref() == Some(account) {
            return Some(RegistryRole::Owner);
        }
        env.storage()
            .persistent()
            .get(&DataKey::OrgRole(org.clone(), account.clone()))
    }

    /// Permission guard for the org-scoped module registrations: the protocol
    /// admin, the org owner, or a delegated role that reaches `kind`.
    ///
    /// The organization record is checked first, ahead of the admin short
    /// circuit, because every one of those three permissions is defined relative
    /// to a recorded owner. An organization that does not exist has no owner to
    /// authorize a registration and no role to delegate one from, so a module
    /// registered against it would be a routing record nobody is accountable
    /// for — not even the protocol admin, who can point it anywhere at any
    /// time. Refusing it here reports [`Error::NotFound`], the same diagnosis
    /// an owner naming a non-existent organization gets, so a caller learns the
    /// organization is missing rather than that it lacks a permission over it.
    fn require_module_permission(
        env: &Env,
        caller: &Address,
        org: &String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        if !env.storage().persistent().has(&DataKey::Org(org.clone())) {
            return Err(Error::NotFound);
        }
        if Self::is_admin(env, caller) {
            return Ok(());
        }
        match Self::effective_role(env, org, caller) {
            Some(role) if role.may_manage(kind) => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }

    /// Read one module record together with its deprecation flag, or `None`
    /// when `(org, kind)` is not registered. Shared by [`Self::lookup`] and
    /// [`Self::get_modules_batch`] so both read a record identically: the TTL is
    /// extended only for a live (non-deprecated) record, as routing has always
    /// done.
    fn read_module(env: &Env, org: String, kind: ModuleKind) -> Option<ModuleInfo> {
        let key = DataKey::Module(org.clone(), kind);
        let address: Address = env.storage().persistent().get(&key)?;
        let deprecated = env
            .storage()
            .persistent()
            .get::<_, bool>(&DataKey::ModuleDeprecated(org, kind))
            .unwrap_or(false);
        if !deprecated {
            Self::bump(env, &key);
        }
        Some(ModuleInfo {
            address,
            deprecated,
        })
    }

    fn bump(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

// ---------------------------------------------------------------------------
// Shared interface implementation. Guarantees the on-chain signatures match the
// generated `RegistryClient` used by other contracts.
// ---------------------------------------------------------------------------
#[contractimpl]
impl RegistryInterface for RegistryContract {
    fn lookup(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        Self::check_frozen(&env)?;
        let module = Self::read_module(&env, org, kind).ok_or(Error::NotFound)?;
        // Routing guard: reject new interactions targeting deprecated modules.
        if module.deprecated {
            return Err(Error::ModuleDeprecated);
        }
        Ok(module.address)
    }

    fn verify_owner(env: Env, org: String, owner: Address) -> Result<bool, Error> {
        Self::check_frozen(&env)?;
        let key = DataKey::Org(org);
        let recorded: Address = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(recorded == owner)
    }

    /// Batch counterpart of [`Self::lookup`]: resolve up to
    /// [`MAX_REGISTRY_BATCH`] module registrations in a single invocation.
    ///
    /// - `result[i]` answers `ids[i]`; length and order are preserved and
    ///   duplicate ids are answered at every position.
    /// - An unregistered id yields `None` instead of failing the batch, so one
    ///   missing module does not hide the others.
    /// - A deprecated module is returned with `deprecated: true` rather than
    ///   [`Error::ModuleDeprecated`]; callers routing to it should refuse it.
    /// - An empty `ids` returns an empty list.
    ///
    /// Errors: [`Error::InvalidInput`] when more than [`MAX_REGISTRY_BATCH`] ids
    /// are requested (checked before any storage is read), and
    /// [`Error::RegistryFrozen`] while the registry is frozen, like every
    /// other lookup on this interface. Read-only: no auth is required.
    fn get_modules_batch(env: Env, ids: Vec<ModuleId>) -> Result<Vec<Option<ModuleInfo>>, Error> {
        ensure!(ids.len() <= MAX_REGISTRY_BATCH, Error::InvalidInput);
        Self::check_frozen(&env)?;
        let mut modules = Vec::new(&env);
        for id in ids.iter() {
            modules.push_back(Self::read_module(&env, id.org, id.kind));
        }
        Ok(modules)
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for RegistryContract {
    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. The first call must come from the registry's
    /// protocol admin, so nobody can claim upgrade rights over the source of
    /// truth between deployment and bootstrap; afterwards only the current
    /// upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        if astroid_interfaces::upgrade::get_authority(&env).is_err() {
            // `set_authority` performs the `require_auth`; checking identity
            // here without a second auth keeps a single signature per call.
            ensure!(Self::is_admin(&env, &caller), Error::Unauthorized);
        }
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    fn get_upgrade_authority(
        env: Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Three gates must pass, in this order, and the contract keeps running its
    /// current code if any of them does:
    ///
    /// 1. `caller` is the recorded upgrade admin and has signed, and `wasm_hash`
    ///    is approved for [`ModuleKind::Organization`] — [`Error::NotInitialized`]
    ///    without a configured authority, [`Error::Unauthorized`] for a stranger
    ///    or unapproved code.
    /// 2. `wasm_hash` is carried by a published `Organization` version, and that
    ///    version is strictly newer than the one this contract runs —
    ///    [`Error::NotFound`] for code the upgrade map does not publish,
    ///    [`Error::CircularUpgrade`] for a downgrade or a no-op, and
    ///    [`Error::InvalidInput`] for a published record that names an account
    ///    rather than a contract. This is the registry's own version upgrade map
    ///    validation, and it is the gate that does not exist for anyone else:
    ///    approval alone cannot order versions.
    /// 3. The swap is applied and [`DataKey::RegistryVersion`] advances to the
    ///    version the target hash resolved to.
    ///
    /// Both gates read this contract's *own* records, which is what makes gate 1
    /// differ from every other member contract's copy of it. Those contracts ask
    /// the registry for an answer, but the registry is the registry: the host
    /// forbids contract re-entry, so a cross-call back into this contract from
    /// inside this contract fails outright — and the shared helper fails closed
    /// on exactly that, which would leave the registry permanently unable to
    /// replace its own code. Reading [`DataKey::ApprovedWasm`] and the version
    /// map directly is the same answer for a third of the cost, and it keeps one
    /// source of truth: the party that can move the registry is the party whose
    /// approval list and published versions are consulted. A foreign registry
    /// recorded as the upgrade authority is therefore not consulted — it could
    /// not loosen anything, since its own administrator had to be this contract's
    /// admin to record it, and `add_approved_wasm` plus `register_version` are
    /// already admin-gated.
    ///
    /// Resolving the target *through* the map is also what makes the ordering
    /// check possible: the version is derived from the hash rather than taken
    /// from the caller, so there is no argument a caller can supply to claim a
    /// forward move while installing backwards code.
    ///
    /// Not gated on the freeze flag: the freeze stops org-scoped writes, and a
    /// registry that could not replace its own code during an incident would be
    /// the one contract nobody could repair.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        // Gate 1: the recorded upgrade admin's signature or multi-admin/multisig
        // signature, then the approval for this kind — the shared rule, resolved
        // against this contract's own approval list for the reason given above.
        caller.require_auth();
        let authority = astroid_interfaces::upgrade::get_authority(&env)?;
        if authority.admin != caller && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        ensure!(
            Self::is_wasm_approved(env.clone(), ModuleKind::Organization, wasm_hash.clone()),
            Error::Unauthorized
        );
        // Gate 2: the version upgrade map. Run before anything is applied, so a
        // refusal leaves the running code and the recorded version untouched.
        let plan = Self::plan_registry_upgrade(&env, &wasm_hash)?;
        // Gate 3. The pin moves with the code in the same invocation, so the
        // version this contract runs can never disagree with the code it runs.
        astroid_interfaces::upgrade::apply(&env, ModuleKind::Organization, wasm_hash)?;
        env.storage()
            .instance()
            .set(&DataKey::RegistryVersion, &plan.to_version);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryUpgraded {
                from_version: plan.from_version,
                to_version: plan.to_version,
                // The binding the map resolved, not the caller's spelling of it.
                // They are equal by construction — the plan matched this exact
                // hash — but the map is the authority, so it is what is logged.
                wasm_hash: plan.wasm_hash,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod test;
