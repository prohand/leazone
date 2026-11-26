import type { components } from "./schema"

type S = components["schemas"]

export type Problem = S["Problem"]
export type Role = S["Role"]
export type SystemInfo = S["SystemInfo"]
export type SessionState = S["SessionState"]
export type SessionStateName = SessionState["state"]
export type MfaMethod = NonNullable<SessionState["mfaMethods"]>[number]
export type EnrollMethod = NonNullable<SessionState["allowedMfaMethods"]>[number]
export type WebAuthnBegin = S["WebAuthnBegin"]
export type WebAuthnFinish = S["WebAuthnFinish"]
export type MfaEnrollResult = S["MfaEnrollResult"]
export type Me = S["Me"]
export type Passkey = S["Passkey"]
export type Session = S["Session"]
export type ApiToken = S["ApiToken"]
export type User = S["User"]
export type SecuritySettings = S["SecuritySettings"]
export type TlsInfo = S["TlsInfo"]
export type AuditEntry = S["AuditEntry"]

// ---- Phase 2: interfaces and DNS ----
export type NetAddress = S["NetAddress"]
export type DnsListener = S["DnsListener"]
export type NetInterface = S["NetInterface"]
export type InterfaceType = NonNullable<NetInterface["type"]>
export type DnsSettings = S["DnsSettings"]
export type DnsStatus = S["DnsStatus"]
export type LookupResult = S["LookupResult"]
export type Soa = S["Soa"]
export type Zone = S["Zone"]
export type ZoneInput = S["ZoneInput"]
export type RecordType = S["RecordType"]
export type DnsRecord = S["Record"]
export type RecordInput = S["RecordInput"]
export type RecordData = S["RecordData"]
export type ForwarderProtocol = S["ForwarderProtocol"]
export type ForwarderInput = S["ForwarderInput"]
export type Forwarder = S["Forwarder"]
export type ForwarderTest = S["ForwarderTest"]

// ---- Phase 3: DHCP, VLANs, import ----
export type Vlan = S["Vlan"]
export type VlanInput = S["VlanInput"]
export type VlanOverview = S["VlanOverview"]
export type VlanInterface = NonNullable<VlanOverview["interfaces"]>[number]
export type ScopeUsage = S["ScopeUsage"]
export type ScopeMode = NonNullable<ScopeUsage["mode"]>
export type DhcpStatus = S["DhcpStatus"]
export type DhcpOption = S["DhcpOption"]
export type DhcpOptionType = DhcpOption["type"]
export type IpRange = S["IpRange"]
export type ScopeInput = S["ScopeInput"]
export type Scope = S["Scope"]
export type ReservationInput = S["ReservationInput"]
export type Reservation = S["Reservation"]
export type Lease = S["Lease"]
export type LeaseState = NonNullable<Lease["state"]>
export type TechnitiumImportInput = S["TechnitiumImportInput"]
export type ImportItem = S["ImportItem"]
export type ImportReport = S["ImportReport"]

// ---- Phase 4: high availability ----
export type ClusterView = S["ClusterView"]
export type ClusterNode = S["ClusterNode"]
export type ClusterRole = S["ClusterRole"]
export type ClusterSettings = S["ClusterSettings"]
export type ClusterWitness = NonNullable<ClusterView["witness"]>
export type ClusterGap = NonNullable<ClusterView["gaps"]>[number]
export type ClusterTerm = NonNullable<ClusterView["history"]>[number]
export type ClusterVip = NonNullable<ClusterView["vip"]>
export type Conflict = S["Conflict"]
