import AgentVMModels
import Darwin
import Dispatch
import Foundation

// MARK: - Virtual Switch Port, FDB, DHCP Lease & Telemetry Snapshots

public struct SwitchPortAttachmentInfo: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID { switchPortID }
    public var switchPortID: UUID
    public var vmID: VMID
    public var assignedMAC: MACAddress
    public var leasedIPv4: IPv4Address?
    public var attachedAt: Date
    public var rxFramesFromGuest: UInt64
    public var txFramesToGuest: UInt64
    public var rxBytesFromGuest: UInt64
    public var txBytesToGuest: UInt64
    public var droppedEgressFrames: UInt64

    public init(
        switchPortID: UUID,
        vmID: VMID,
        assignedMAC: MACAddress,
        leasedIPv4: IPv4Address? = nil,
        attachedAt: Date = Date(),
        rxFramesFromGuest: UInt64 = 0,
        txFramesToGuest: UInt64 = 0,
        rxBytesFromGuest: UInt64 = 0,
        txBytesToGuest: UInt64 = 0,
        droppedEgressFrames: UInt64 = 0
    ) {
        self.switchPortID = switchPortID
        self.vmID = vmID
        self.assignedMAC = assignedMAC
        self.leasedIPv4 = leasedIPv4
        self.attachedAt = attachedAt
        self.rxFramesFromGuest = rxFramesFromGuest
        self.txFramesToGuest = txFramesToGuest
        self.rxBytesFromGuest = rxBytesFromGuest
        self.txBytesToGuest = txBytesToGuest
        self.droppedEgressFrames = droppedEgressFrames
    }
}

public struct MACForwardingEntry: Codable, Hashable, Sendable, Identifiable {
    public var id: String { macAddress.description }
    public var macAddress: MACAddress
    public var vmID: VMID
    public var switchPortID: UUID
    public var isStaticPortBinding: Bool
    public var learnedAt: Date
    public var lastSeenAt: Date
    public var framesObserved: UInt64

    public init(
        macAddress: MACAddress,
        vmID: VMID,
        switchPortID: UUID,
        isStaticPortBinding: Bool,
        learnedAt: Date,
        lastSeenAt: Date,
        framesObserved: UInt64
    ) {
        self.macAddress = macAddress
        self.vmID = vmID
        self.switchPortID = switchPortID
        self.isStaticPortBinding = isStaticPortBinding
        self.learnedAt = learnedAt
        self.lastSeenAt = lastSeenAt
        self.framesObserved = framesObserved
    }
}

public struct DHCPLeaseRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: String { clientMAC.description }
    public var clientMAC: MACAddress
    public var vmID: VMID?
    public var ipv4Address: IPv4Address
    public var subnetMask: IPv4Address
    public var routerIP: IPv4Address
    public var hostname: String?
    public var leaseSeconds: UInt32
    public var isCommittedACK: Bool
    public var issuedAt: Date
    public var expiresAt: Date

    public init(
        clientMAC: MACAddress,
        vmID: VMID?,
        ipv4Address: IPv4Address,
        subnetMask: IPv4Address,
        routerIP: IPv4Address,
        hostname: String?,
        leaseSeconds: UInt32,
        isCommittedACK: Bool,
        issuedAt: Date,
        expiresAt: Date
    ) {
        self.clientMAC = clientMAC
        self.vmID = vmID
        self.ipv4Address = ipv4Address
        self.subnetMask = subnetMask
        self.routerIP = routerIP
        self.hostname = hostname
        self.leaseSeconds = leaseSeconds
        self.isCommittedACK = isCommittedACK
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }
}

public struct SwitchStatisticsSnapshot: Codable, Hashable, Sendable {
    public var subnetCIDR: String
    public var gatewayIP: String
    public var gatewayMAC: String
    public var attachedPortCount: Int
    public var fdbEntryCount: Int
    public var activeDHCPLeaseCount: Int
    public var capturedRingCount: Int
    public var capturedRingCapacity: Int
    public var totalFramesProcessed: UInt64
    public var totalSwitchRepliesGenerated: UInt64
    public var totalDroppedFrames: UInt64

    public init(
        subnetCIDR: String,
        gatewayIP: String,
        gatewayMAC: String,
        attachedPortCount: Int,
        fdbEntryCount: Int,
        activeDHCPLeaseCount: Int,
        capturedRingCount: Int,
        capturedRingCapacity: Int,
        totalFramesProcessed: UInt64,
        totalSwitchRepliesGenerated: UInt64,
        totalDroppedFrames: UInt64
    ) {
        self.subnetCIDR = subnetCIDR
        self.gatewayIP = gatewayIP
        self.gatewayMAC = gatewayMAC
        self.attachedPortCount = attachedPortCount
        self.fdbEntryCount = fdbEntryCount
        self.activeDHCPLeaseCount = activeDHCPLeaseCount
        self.capturedRingCount = capturedRingCount
        self.capturedRingCapacity = capturedRingCapacity
        self.totalFramesProcessed = totalFramesProcessed
        self.totalSwitchRepliesGenerated = totalSwitchRepliesGenerated
        self.totalDroppedFrames = totalDroppedFrames
    }
}

// MARK: - O(1) Bounded Ring Buffer for Captured Packets

private struct PacketCaptureRingBuffer: Sendable {
    let capacity: Int
    private var storage: [CapturedPacket?]
    private var writeIndex: Int = 0
    private(set) var count: Int = 0

    init(capacity: Int) {
        let clamped = max(16, capacity)
        self.capacity = clamped
        self.storage = [CapturedPacket?](repeating: nil, count: clamped)
    }

    mutating func append(_ packet: CapturedPacket) {
        storage[writeIndex] = packet
        writeIndex = (writeIndex + 1) % capacity
        if count < capacity {
            count += 1
        }
    }

    mutating func clear() {
        storage = [CapturedPacket?](repeating: nil, count: capacity)
        writeIndex = 0
        count = 0
    }

    func chronologicalPackets() -> [CapturedPacket] {
        guard count > 0 else { return [] }
        var result: [CapturedPacket] = []
        result.reserveCapacity(count)
        let oldestIndex = count == capacity ? writeIndex : 0
        for offset in 0..<count {
            let idx = (oldestIndex + offset) % capacity
            if let pkt = storage[idx] {
                result.append(pkt)
            }
        }
        return result
    }
}

// MARK: - Race-Free Non-Blocking UNIX Datagram Port Channel

private final class SwitchPortSocketHandle: @unchecked Sendable {
    let portID: UUID
    let vmID: VMID
    private let lock = NSLock()
    private var switchSideFD: Int32
    private var isClosed: Bool = false
    private let readSource: DispatchSourceRead

    init(
        portID: UUID,
        vmID: VMID,
        switchSideFD: Int32,
        ioQueue: DispatchQueue,
        onFrame: @escaping @Sendable (Data) -> Void
    ) {
        self.portID = portID
        self.vmID = vmID
        self.switchSideFD = switchSideFD

        let source = DispatchSource.makeReadSource(fileDescriptor: switchSideFD, queue: ioQueue)
        self.readSource = source

        source.setEventHandler { [weak self] in
            guard let self else { return }
            let frames = self.drainAvailableFrames()
            for frame in frames {
                onFrame(frame)
            }
        }

        source.setCancelHandler { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let fd = self.switchSideFD
            self.switchSideFD = -1
            self.lock.unlock()
            if fd >= 0 {
                _ = Darwin.close(fd)
            }
        }

        source.resume()
    }

    deinit {
        closeIdempotent()
    }

    private func drainAvailableFrames() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        guard !isClosed, switchSideFD >= 0 else { return [] }

        var frames: [Data] = []
        var buffer = [UInt8](repeating: 0, count: 9216) // Jumbo Ethernet MTU headroom

        while true {
            let n = buffer.withUnsafeMutableBytes { rawPtr -> Int in
                guard let base = rawPtr.baseAddress else { return -1 }
                return Darwin.recv(switchSideFD, base, rawPtr.count, 0)
            }
            if n > 0 {
                frames.append(Data(buffer[0..<n]))
            } else {
                break
            }
        }
        return frames
    }

    func sendDatagram(_ frame: Data) {
        guard !frame.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        guard !isClosed, switchSideFD >= 0 else { return }
        _ = frame.withUnsafeBytes { rawPtr in
            guard let base = rawPtr.baseAddress else { return -1 }
            return Darwin.send(switchSideFD, base, rawPtr.count, 0)
        }
    }

    func closeIdempotent() {
        lock.lock()
        if isClosed {
            lock.unlock()
            return
        }
        isClosed = true
        lock.unlock()
        readSource.cancel()
    }
}

// MARK: - User-Space Layer-2 Virtual Switch + Built-In DHCP/ARP/DNS/RST Engine

public actor UserSpaceL2Switch {
    public nonisolated let subnetCIDR: IPv4CIDR
    public nonisolated let gatewayIP: IPv4Address
    public nonisolated let gatewayMAC: MACAddress
    public nonisolated let firewall: EgressFirewallEngine

    private let dissector = PacketDissector(verifyChecksums: true)
    private let crafter = PacketFrameCrafter()
    private let socketIOQueue = DispatchQueue(
        label: "com.agentvm.netswitch.socketpair-io",
        qos: .userInitiated
    )

    private struct AttachedPortRecord {
        var info: SwitchPortAttachmentInfo
        var socketHandle: SwitchPortSocketHandle?
    }

    private var portsByVMID: [VMID: AttachedPortRecord] = [:]
    private var fdbTable: [MACAddress: MACForwardingEntry] = [:]
    private var dhcpLeasesByMAC: [MACAddress: DHCPLeaseRecord] = [:]
    private var dhcpPoolAddresses: [IPv4Address]
    private var staticDNSRecords: [String: IPv4Address]
    private var captureRing: PacketCaptureRingBuffer

    private var nextPacketSequence: UInt64 = 1
    private var totalFramesProcessed: UInt64 = 0
    private var totalSwitchRepliesGenerated: UInt64 = 0
    private var totalDroppedFrames: UInt64 = 0

    public init(
        subnetCIDR: IPv4CIDR = IPv4CIDR(network: IPv4Address(a: 10, b: 211, c: 55, d: 0), prefixLength: 24)!,
        gatewayIP: IPv4Address = .switchGateway,
        firewall: EgressFirewallEngine = EgressFirewallEngine(),
        ringBufferCapacity: Int = 10_000
    ) {
        self.subnetCIDR = subnetCIDR
        self.gatewayIP = gatewayIP
        self.gatewayMAC = .defaultGateway
        self.firewall = firewall
        self.captureRing = PacketCaptureRingBuffer(capacity: ringBufferCapacity)
        self.dhcpPoolAddresses = Self.computeDHCPLeasePool(subnet: subnetCIDR, gatewayIP: gatewayIP)
        self.staticDNSRecords = Self.defaultCuratedDNSRecords()
    }

    public init(
        subnetCIDR: String,
        gatewayIP: String = "10.211.55.1",
        firewall: EgressFirewallEngine = EgressFirewallEngine(),
        ringBufferCapacity: Int = 10_000
    ) {
        let resolvedCIDR = IPv4CIDR(parsing: subnetCIDR)
            ?? IPv4CIDR(network: IPv4Address(a: 10, b: 211, c: 55, d: 0), prefixLength: 24)!
        let resolvedGW = IPv4Address(parsing: gatewayIP) ?? .switchGateway
        self.init(
            subnetCIDR: resolvedCIDR,
            gatewayIP: resolvedGW,
            firewall: firewall,
            ringBufferCapacity: ringBufferCapacity
        )
    }

    // MARK: - Virtual Switch Port Lifecycle (`VZFileHandleNetworkDeviceAttachment` Ready)

    /// Creates a connected `AF_UNIX` `SOCK_DGRAM` socketpair for a guest NIC.
    /// Ownership of `vmSideFD` transfers to the caller (e.g. `FileHandle(fileDescriptor: vmSideFD, closeOnDealloc: true)`),
    /// while the switch retains and monitors the internal switch-side socket descriptor.
    public func createPortSocketPair(
        for vmID: VMID,
        macAddress: MACAddress
    ) throws -> (vmSideFD: Int32, switchPortID: UUID) {
        // Cleanly tear down any prior port attached for the same VM
        detachPort(for: vmID)

        var fds: [Int32] = [-1, -1]
        let rc = Darwin.socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        guard rc == 0 else {
            let err = Darwin.errno
            throw AgentVMError.diskImageOperationFailed(
                path: "socketpair(AF_UNIX,SOCK_DGRAM)",
                errnoCode: err,
                detail: "Unable to allocate UNIX datagram socketpair for VM '\(vmID.rawValue)'."
            )
        }

        let switchFD = fds[0]
        let vmSideFD = fds[1]

        Self.configureDatagramSocket(fd: switchFD, nonBlocking: true)
        Self.configureDatagramSocket(fd: vmSideFD, nonBlocking: false)

        let portID = UUID()
        let handle = SwitchPortSocketHandle(
            portID: portID,
            vmID: vmID,
            switchSideFD: switchFD,
            ioQueue: socketIOQueue
        ) { [weak self] incomingFrame in
            guard let self else { return }
            Task {
                _ = try? await self.injectFrameFromGuest(vmID: vmID, rawFrame: incomingFrame)
            }
        }

        let now = Date()
        let portInfo = SwitchPortAttachmentInfo(
            switchPortID: portID,
            vmID: vmID,
            assignedMAC: macAddress,
            leasedIPv4: dhcpLeasesByMAC[macAddress]?.ipv4Address,
            attachedAt: now
        )
        portsByVMID[vmID] = AttachedPortRecord(info: portInfo, socketHandle: handle)

        fdbTable[macAddress] = MACForwardingEntry(
            macAddress: macAddress,
            vmID: vmID,
            switchPortID: portID,
            isStaticPortBinding: true,
            learnedAt: now,
            lastSeenAt: now,
            framesObserved: 0
        )

        return (vmSideFD: vmSideFD, switchPortID: portID)
    }

    public func createPortSocketPair(
        for vmID: VMID,
        macAddress: String
    ) throws -> (vmSideFD: Int32, switchPortID: UUID) {
        guard let parsedMAC = MACAddress(parsing: macAddress) else {
            throw AgentVMError.invalidConfiguration(issues: [
                ValidationIssue(
                    fieldPath: "macAddress",
                    code: "INVALID_MAC_ADDRESS",
                    message: "Malformed MAC address '\(macAddress)'.",
                    remediation: "Provide a 6-octet hex MAC address such as '52:54:00:10:20:30'."
                )
            ])
        }
        return try createPortSocketPair(for: vmID, macAddress: parsedMAC)
    }

    public func detachPort(for vmID: VMID) {
        guard let removed = portsByVMID.removeValue(forKey: vmID) else {
            return
        }
        removed.socketHandle?.closeIdempotent()
        fdbTable = fdbTable.filter { $0.value.vmID != vmID }
    }

    // MARK: - Core L2 Frame Switching, DPI Firewall Enforcement & Protocol Responders

    public func injectFrameFromGuest(
        vmID: VMID,
        rawFrame: Data
    ) async throws -> (captured: CapturedPacket, switchGeneratedReplies: [Data]) {
        let seq = allocateSequenceNumber()
        let timestamp = Self.nowMicroseconds()

        // Determine if frame is lateral VM-to-VM unicast vs standard egress
        let dstMACCandidate = rawFrame.count >= 6
            ? MACAddress(octets: Array(rawFrame.prefix(6)))
            : nil
        let isLateralPeerFrame: Bool
        if let dstMAC = dstMACCandidate,
           !dstMAC.isBroadcast,
           dstMAC != gatewayMAC,
           let fdbHit = fdbTable[dstMAC],
           fdbHit.vmID != vmID {
            isLateralPeerFrame = true
        } else {
            isLateralPeerFrame = false
        }

        var captured = try dissector.dissectEthernetFrame(
            rawFrame,
            sequenceNumber: seq,
            timestampMicros: timestamp,
            vmID: vmID,
            direction: isLateralPeerFrame ? .lateralVMToVM : .egress
        )

        // 1. Update MAC Learning Forwarding Database (FDB)
        if let srcMAC = MACAddress(parsing: captured.sourceMAC), !srcMAC.isMulticast {
            learnSourceMAC(srcMAC, vmID: vmID)
        }

        // 2. Evaluate Egress / Lateral Firewall Policy
        let evaluation = await firewall.evaluate(captured)
        captured.verdict = evaluation.verdict
        captured.matchedRuleID = evaluation.ruleID
        captured.verdictReason = evaluation.reason

        // 3. Record Captured Frame & Port Telemetry
        captureRing.append(captured)
        totalFramesProcessed &+= 1
        if var portRecord = portsByVMID[vmID] {
            portRecord.info.rxFramesFromGuest &+= 1
            portRecord.info.rxBytesFromGuest &+= UInt64(rawFrame.count)
            if !evaluation.verdict.isPermitted {
                portRecord.info.droppedEgressFrames &+= 1
            }
            portsByVMID[vmID] = portRecord
        }
        if !evaluation.verdict.isPermitted {
            totalDroppedFrames &+= 1
        }

        // 4. Generate Active Switch Enforcement / Service Replies
        var generatedReplies: [Data] = []

        switch evaluation.verdict {
        case .dnsSinkhole:
            if let sinkholeFrame = try? crafter.buildDNSResponse(
                forRequest: rawFrame,
                resolvedIPv4: .zero,
                rcode: 0,
                ttl: 60
            ) {
                recordSwitchGeneratedReply(
                    sinkholeFrame,
                    for: vmID,
                    verdict: .dnsSinkhole,
                    ruleID: evaluation.ruleID,
                    reason: "Switch DNS Sinkhole responder (0.0.0.0)"
                )
                generatedReplies.append(sinkholeFrame)
            }

        case .rejectRST:
            if let rstFrame = try? crafter.buildTCPRSTReply(forIncomingFrame: rawFrame) {
                recordSwitchGeneratedReply(
                    rstFrame,
                    for: vmID,
                    verdict: .rejectRST,
                    ruleID: evaluation.ruleID,
                    reason: "Switch injected TCP RST on rejected flow"
                )
                generatedReplies.append(rstFrame)
            }

        case .drop, .rateLimited, .pluginBlocked:
            break

        case .allow:
            let serviceReplies = await handleAllowedGuestFrame(
                vmID: vmID,
                rawFrame: rawFrame,
                dissected: captured
            )
            generatedReplies.append(contentsOf: serviceReplies)

            // Forward lateral unicast or broadcast frames to other attached VM ports
            forwardLateralFrameIfApplicable(
                senderVMID: vmID,
                dstMAC: dstMACCandidate,
                rawFrame: rawFrame
            )
        }

        // Push switch-generated replies onto the guest's UNIX datagram socketpair if attached
        if !generatedReplies.isEmpty, var portRecord = portsByVMID[vmID] {
            for reply in generatedReplies {
                portRecord.socketHandle?.sendDatagram(reply)
                portRecord.info.txFramesToGuest &+= 1
                portRecord.info.txBytesToGuest &+= UInt64(reply.count)
            }
            portsByVMID[vmID] = portRecord
        }

        return (captured: captured, switchGeneratedReplies: generatedReplies)
    }

    private func handleAllowedGuestFrame(
        vmID: VMID,
        rawFrame: Data,
        dissected: CapturedPacket
    ) async -> [Data] {
        let bytes = [UInt8](rawFrame)
        var replies: [Data] = []

        // A. Built-in Gateway ARP Responder (0x0806)
        if dissected.etherType == 0x0806 {
            let l3Offset = dissected.vlanID != nil ? 18 : 14
            if let arp = try? dissector.parseARPHeader(bytes: bytes, offset: l3Offset),
               arp.opcode == 1,
               arp.targetIP == gatewayIP {
                let arpReply = crafter.buildARPPacket(
                    isReply: true,
                    senderMAC: gatewayMAC,
                    senderIP: gatewayIP,
                    targetMAC: arp.senderMAC,
                    targetIP: arp.senderIP
                )
                recordSwitchGeneratedReply(
                    arpReply,
                    for: vmID,
                    verdict: .allow,
                    ruleID: nil,
                    reason: "Switch Gateway ARP Reply (\(gatewayIP) is-at \(gatewayMAC))"
                )
                replies.append(arpReply)
            }
            return replies
        }

        guard dissected.etherType == 0x0800 else {
            return replies
        }

        let l3Offset = dissected.vlanID != nil ? 18 : 14
        guard bytes.count >= l3Offset + 20 else { return replies }
        let ihl = Int(bytes[l3Offset] & 0x0F) * 4
        let ipTotalLen = Int((UInt16(bytes[l3Offset + 2]) << 8) | UInt16(bytes[l3Offset + 3]))
        let ipEnd = min(bytes.count, l3Offset + ipTotalLen)
        let l4Offset = l3Offset + ihl
        guard l4Offset <= ipEnd else { return replies }

        // B. Built-in DHCPv4 Server (UDP dstPort 67, Pool 10.211.55.10 ... 10.211.55.240)
        if dissected.highestProtocol == .dhcp,
           dissected.destinationPort == 67,
           l4Offset + 8 <= ipEnd {
            if let dhcpReply = handleDHCPv4ClientFrame(
                vmID: vmID,
                bytes: bytes,
                dhcpOffset: l4Offset + 8,
                dhcpEnd: ipEnd
            ) {
                recordSwitchGeneratedReply(
                    dhcpReply,
                    for: vmID,
                    verdict: .allow,
                    ruleID: dissected.matchedRuleID,
                    reason: "Switch Built-in DHCPv4 Lease Responder"
                )
                replies.append(dhcpReply)
            }
            return replies
        }

        // C. Built-in Gateway ICMPv4 Echo (Ping) Responder
        if dissected.highestProtocol == .icmp,
           dissected.destinationIP == gatewayIP.description,
           l4Offset + 8 <= ipEnd,
           bytes[l4Offset] == 8, // Echo Request
           bytes[l4Offset + 1] == 0 {
            if let guestMAC = MACAddress(parsing: dissected.sourceMAC),
               let guestIPStr = dissected.sourceIP,
               let guestIP = IPv4Address(parsing: guestIPStr) {
                let ident = (UInt16(bytes[l4Offset + 4]) << 8) | UInt16(bytes[l4Offset + 5])
                let seqNum = (UInt16(bytes[l4Offset + 6]) << 8) | UInt16(bytes[l4Offset + 7])
                let echoPayload = Data(bytes[(l4Offset + 8)..<ipEnd])

                let echoReply = crafter.buildICMPv4Echo(
                    isReply: true,
                    srcMAC: gatewayMAC,
                    dstMAC: guestMAC,
                    srcIP: gatewayIP,
                    dstIP: guestIP,
                    identifier: ident,
                    sequence: seqNum,
                    payload: echoPayload
                )
                recordSwitchGeneratedReply(
                    echoReply,
                    for: vmID,
                    verdict: .allow,
                    ruleID: nil,
                    reason: "Switch Gateway ICMPv4 Echo Reply"
                )
                replies.append(echoReply)
            }
            return replies
        }

        // D. Built-in Switch DNS Resolver & Firewall DNS->IPv4 Correlation Populator
        if dissected.highestProtocol == .dns,
           dissected.destinationPort == 53,
           let qname = dissected.dnsQueryName,
           l4Offset + 20 <= ipEnd {
            let dnsFlags = (UInt16(bytes[l4Offset + 8 + 2]) << 8) | UInt16(bytes[l4Offset + 8 + 3])
            let isQuery = (dnsFlags & 0x8000) == 0
            if isQuery {
                let resolvedIP = resolveDomainToIPv4(qname)
                await firewall.recordDNSResolution(domain: qname, ipv4: resolvedIP, ttlSeconds: 300)

                if let dnsReply = try? crafter.buildDNSResponse(
                    forRequest: rawFrame,
                    resolvedIPv4: resolvedIP,
                    rcode: 0,
                    ttl: 300
                ) {
                    recordSwitchGeneratedReply(
                        dnsReply,
                        for: vmID,
                        verdict: .allow,
                        ruleID: dissected.matchedRuleID,
                        reason: "Switch DNS Resolver (\(qname) -> \(resolvedIP))"
                    )
                    replies.append(dnsReply)
                }
            }
        }

        return replies
    }

    private func handleDHCPv4ClientFrame(
        vmID: VMID,
        bytes: [UInt8],
        dhcpOffset: Int,
        dhcpEnd: Int
    ) -> Data? {
        guard let dhcpMsg = try? dissector.parseDHCPv4Message(
            bytes: bytes,
            offset: dhcpOffset,
            end: dhcpEnd
        ), let msgType = dhcpMsg.messageType else {
            return nil
        }

        let clientMAC = dhcpMsg.clientMAC
        let leaseDuration: UInt32 = 86_400

        switch msgType {
        case 1: // DHCPDISCOVER -> DHCPOFFER (2)
            guard let offeredIP = allocateOrReuseLeaseIP(
                for: clientMAC,
                vmID: vmID,
                requestedIP: dhcpMsg.requestedIP,
                hostname: dhcpMsg.hostname,
                commitACK: false,
                leaseSeconds: leaseDuration
            ) else {
                return nil
            }
            return crafter.buildDHCPv4Packet(
                messageType: 2,
                transactionID: dhcpMsg.transactionID,
                clientMAC: clientMAC,
                yourIP: offeredIP,
                serverIP: gatewayIP,
                subnetMask: subnetCIDR.netmask,
                routerIP: gatewayIP,
                dnsServers: [gatewayIP],
                leaseSeconds: leaseDuration,
                hostname: dhcpMsg.hostname
            )

        case 3: // DHCPREQUEST -> DHCPACK (5) or DHCPNAK (6)
            let desiredIP = dhcpMsg.requestedIP
                ?? (dhcpMsg.clientIP != .zero ? dhcpMsg.clientIP : dhcpLeasesByMAC[clientMAC]?.ipv4Address)

            if let requested = desiredIP,
               (!subnetCIDR.contains(requested) || requested == gatewayIP || isIPOwnedByAnotherMAC(requested, requester: clientMAC)) {
                return crafter.buildDHCPv4Packet(
                    messageType: 6, // DHCPNAK
                    transactionID: dhcpMsg.transactionID,
                    clientMAC: clientMAC,
                    yourIP: .zero,
                    serverIP: gatewayIP,
                    subnetMask: subnetCIDR.netmask,
                    routerIP: gatewayIP,
                    dnsServers: [gatewayIP],
                    leaseSeconds: 0,
                    hostname: dhcpMsg.hostname
                )
            }

            guard let committedIP = allocateOrReuseLeaseIP(
                for: clientMAC,
                vmID: vmID,
                requestedIP: desiredIP,
                hostname: dhcpMsg.hostname,
                commitACK: true,
                leaseSeconds: leaseDuration
            ) else {
                return nil
            }

            if var portRecord = portsByVMID[vmID] {
                portRecord.info.leasedIPv4 = committedIP
                portsByVMID[vmID] = portRecord
            }

            return crafter.buildDHCPv4Packet(
                messageType: 5, // DHCPACK
                transactionID: dhcpMsg.transactionID,
                clientMAC: clientMAC,
                yourIP: committedIP,
                serverIP: gatewayIP,
                subnetMask: subnetCIDR.netmask,
                routerIP: gatewayIP,
                dnsServers: [gatewayIP],
                leaseSeconds: leaseDuration,
                hostname: dhcpMsg.hostname
            )

        case 7: // DHCPRELEASE
            dhcpLeasesByMAC.removeValue(forKey: clientMAC)
            return nil

        case 8: // DHCPINFORM -> DHCPACK (5)
            let clientIP = dhcpMsg.clientIP != .zero
                ? dhcpMsg.clientIP
                : (dhcpLeasesByMAC[clientMAC]?.ipv4Address ?? .zero)
            return crafter.buildDHCPv4Packet(
                messageType: 5,
                transactionID: dhcpMsg.transactionID,
                clientMAC: clientMAC,
                yourIP: clientIP,
                serverIP: gatewayIP,
                subnetMask: subnetCIDR.netmask,
                routerIP: gatewayIP,
                dnsServers: [gatewayIP],
                leaseSeconds: leaseDuration,
                hostname: dhcpMsg.hostname
            )

        default:
            return nil
        }
    }

    // MARK: - Packet Wiretap Querying, PCAPNG Export & Demonstration Traffic Seeder

    public func recentPackets(
        limit: Int = 500,
        filterQuery: String? = nil
    ) -> [CapturedPacket] {
        guard limit > 0 else { return [] }
        let ordered = captureRing.chronologicalPackets()
        let filtered: [CapturedPacket]
        if let filterQuery, !filterQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let parsed = WiretapFilterQuery(filterQuery)
            filtered = parsed.filter(ordered)
        } else {
            filtered = ordered
        }
        if filtered.count <= limit {
            return filtered
        }
        return Array(filtered.suffix(limit))
    }

    public func recentPackets(
        limit: Int = 500,
        filterQuery: WiretapFilterQuery
    ) -> [CapturedPacket] {
        guard limit > 0 else { return [] }
        let filtered = filterQuery.filter(captureRing.chronologicalPackets())
        if filtered.count <= limit {
            return filtered
        }
        return Array(filtered.suffix(limit))
    }

    public func exportPCAPNG(to url: URL) throws {
        let snapshot = captureRing.chronologicalPackets()
        try PCAPNGCodec().writeCaptureFile(
            packets: snapshot,
            to: url,
            hardwareDescription: "AgentVM UserSpace L2 Switch (\(subnetCIDR.description))"
        )
    }

    public func exportPCAPNGData(filterQuery: String? = nil) -> Data {
        let packets = recentPackets(limit: captureRing.capacity, filterQuery: filterQuery)
        return PCAPNGCodec().encodeCapture(
            packets: packets,
            hardwareDescription: "AgentVM UserSpace L2 Switch (\(subnetCIDR.description))"
        )
    }

    public func clearCapturedPackets() {
        captureRing.clear()
    }

    /// Synthesizes a multi-protocol sequence of realistic guest frames (ARP, DHCPv4 DORA, ICMPv4 Ping,
    /// DNS resolution + Sinkhole block, TLS 1.3 ClientHello SNI/ALPN handshakes, and SSRF Metadata Drop)
    /// through the full switch & firewall pipeline.
    public func seedDemonstrationTraffic(for vmID: VMID) async throws -> [CapturedPacket] {
        let beforeSeq = nextPacketSequence
        let guestMAC = portsByVMID[vmID]?.info.assignedMAC
            ?? MACAddress.deterministicGuestMAC(seed: vmID.rawValue)

        // 1. DHCPv4 DORA Handshake (Discover -> Offer -> Request -> ACK)
        let dhcpTxID: UInt32 = 0x4156_2026
        let discoverFrame = crafter.buildDHCPv4Packet(
            messageType: 1,
            transactionID: dhcpTxID,
            clientMAC: guestMAC,
            yourIP: .zero,
            serverIP: .zero,
            subnetMask: subnetCIDR.netmask,
            routerIP: gatewayIP,
            dnsServers: [gatewayIP],
            hostname: vmID.rawValue
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: discoverFrame)

        let leasedIP = dhcpLeasesByMAC[guestMAC]?.ipv4Address
            ?? dhcpPoolAddresses.first
            ?? IPv4Address(a: 10, b: 211, c: 55, d: 10)

        let requestFrame = crafter.buildDHCPv4Packet(
            messageType: 3,
            transactionID: dhcpTxID,
            clientMAC: guestMAC,
            yourIP: leasedIP,
            serverIP: gatewayIP,
            subnetMask: subnetCIDR.netmask,
            routerIP: gatewayIP,
            dnsServers: [gatewayIP],
            hostname: vmID.rawValue
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: requestFrame)

        // 2. Gateway ARP Request -> Gateway ARP Reply
        let arpReq = crafter.buildARPPacket(
            isReply: false,
            senderMAC: guestMAC,
            senderIP: leasedIP,
            targetMAC: .broadcast,
            targetIP: gatewayIP
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: arpReq)

        // 3. Gateway ICMPv4 Echo Ping -> Echo Reply
        let pingReq = crafter.buildICMPv4Echo(
            isReply: false,
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: gatewayIP,
            identifier: 0x0A01,
            sequence: 1,
            payload: Data("agentvm-l2-heartbeat".utf8)
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: pingReq)

        // 4. Audited DNS Query + TLS 1.3 ClientHello to Anthropic API (ALLOW)
        let dnsAnthropic = crafter.buildDNSQuery(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: gatewayIP,
            srcPort: 54101,
            transactionID: 0x2101,
            qname: "api.anthropic.com"
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: dnsAnthropic)

        let anthropicIP = resolveDomainToIPv4("api.anthropic.com")
        let synAnthropic = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: anthropicIP,
            srcPort: 51400,
            dstPort: 443,
            seq: 1_000_000,
            ack: 0,
            flags: [.syn]
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: synAnthropic)

        let chAnthropic = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: anthropicIP,
            srcPort: 51400,
            dstPort: 443,
            seq: 1_000_001,
            ack: 4_000_001,
            flags: [.psh, .ack],
            payload: crafter.buildTLSClientHelloPayload(
                serverName: "api.anthropic.com",
                alpnProtocols: ["h2", "http/1.1"]
            )
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: chAnthropic)

        // 5. Audited DNS Query + TLS 1.3 ClientHello to GitHub (ALLOW)
        let dnsGitHub = crafter.buildDNSQuery(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: gatewayIP,
            srcPort: 54102,
            transactionID: 0x2102,
            qname: "github.com"
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: dnsGitHub)

        let githubIP = resolveDomainToIPv4("github.com")
        let chGitHub = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: githubIP,
            srcPort: 51402,
            dstPort: 443,
            seq: 2_000_001,
            ack: 8_000_001,
            flags: [.psh, .ack],
            payload: crafter.buildTLSClientHelloPayload(
                serverName: "github.com",
                alpnProtocols: ["h2", "http/1.1"]
            )
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: chGitHub)

        // 6. Exfiltration Webhook Sinkhole Trigger (DNS_SINKHOLE -> 0.0.0.0)
        let dnsWebhook = crafter.buildDNSQuery(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: gatewayIP,
            srcPort: 54103,
            transactionID: 0x2103,
            qname: "leak-secrets.webhook.site"
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: dnsWebhook)

        // 7. Cloud Metadata SSRF Credential Harvest Attempt (169.254.169.254 -> DROP)
        let metadataIP = IPv4Address(a: 169, b: 254, c: 169, d: 254)
        let ssrfHTTP = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: metadataIP,
            srcPort: 51408,
            dstPort: 80,
            seq: 3_000_001,
            ack: 1,
            flags: [.psh, .ack],
            payload: crafter.buildHTTPRequestPayload(
                method: "GET",
                path: "/latest/meta-data/iam/security-credentials/",
                host: "169.254.169.254"
            )
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: ssrfHTTP)

        // 8. Unauthorized Unknown C2 TLS Endpoint (DROP by Default Egress Policy)
        let untrustedIP = IPv4Address(a: 198, b: 51, c: 100, d: 99)
        let untrustedTLS = crafter.buildTCPFrame(
            srcMAC: guestMAC,
            dstMAC: gatewayMAC,
            srcIP: leasedIP,
            dstIP: untrustedIP,
            srcPort: 51409,
            dstPort: 443,
            seq: 4_000_001,
            ack: 1,
            flags: [.psh, .ack],
            payload: crafter.buildTLSClientHelloPayload(
                serverName: "untrusted-c2.example.net",
                alpnProtocols: ["http/1.1"]
            )
        )
        _ = try await injectFrameFromGuest(vmID: vmID, rawFrame: untrustedTLS)

        return captureRing.chronologicalPackets().filter { $0.sequenceNumber >= beforeSeq }
    }

    // MARK: - Switch Diagnostics, FDB, DHCP Leases & DNS Record Management

    public func attachedPorts() -> [SwitchPortAttachmentInfo] {
        portsByVMID.values
            .map(\.info)
            .sorted { $0.vmID < $1.vmID }
    }

    public func forwardingTable() -> [MACForwardingEntry] {
        fdbTable.values.sorted { $0.macAddress.description < $1.macAddress.description }
    }

    public func dhcpLeases() -> [DHCPLeaseRecord] {
        dhcpLeasesByMAC.values.sorted { $0.ipv4Address < $1.ipv4Address }
    }

    public func registerStaticDNSRecord(domain: String, ipv4: IPv4Address) {
        let clean = domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
        guard !clean.isEmpty else { return }
        staticDNSRecords[clean] = ipv4
    }

    public func statistics() -> SwitchStatisticsSnapshot {
        SwitchStatisticsSnapshot(
            subnetCIDR: subnetCIDR.description,
            gatewayIP: gatewayIP.description,
            gatewayMAC: gatewayMAC.description,
            attachedPortCount: portsByVMID.count,
            fdbEntryCount: fdbTable.count,
            activeDHCPLeaseCount: dhcpLeasesByMAC.count,
            capturedRingCount: captureRing.count,
            capturedRingCapacity: captureRing.capacity,
            totalFramesProcessed: totalFramesProcessed,
            totalSwitchRepliesGenerated: totalSwitchRepliesGenerated,
            totalDroppedFrames: totalDroppedFrames
        )
    }

    // MARK: - Internal Helpers

    private func allocateSequenceNumber() -> UInt64 {
        defer { nextPacketSequence &+= 1 }
        return nextPacketSequence
    }

    private func learnSourceMAC(_ mac: MACAddress, vmID: VMID) {
        let now = Date()
        if var existing = fdbTable[mac] {
            existing.vmID = vmID
            if let portID = portsByVMID[vmID]?.info.switchPortID {
                existing.switchPortID = portID
            }
            existing.lastSeenAt = now
            existing.framesObserved &+= 1
            fdbTable[mac] = existing
        } else {
            let portID = portsByVMID[vmID]?.info.switchPortID ?? UUID()
            fdbTable[mac] = MACForwardingEntry(
                macAddress: mac,
                vmID: vmID,
                switchPortID: portID,
                isStaticPortBinding: false,
                learnedAt: now,
                lastSeenAt: now,
                framesObserved: 1
            )
        }
    }

    private func recordSwitchGeneratedReply(
        _ frame: Data,
        for vmID: VMID,
        verdict: FirewallVerdict,
        ruleID: RuleID?,
        reason: String
    ) {
        let seq = allocateSequenceNumber()
        let ts = Self.nowMicroseconds()
        guard var replyPacket = try? dissector.dissectEthernetFrame(
            frame,
            sequenceNumber: seq,
            timestampMicros: ts,
            vmID: vmID,
            direction: .ingress
        ) else {
            return
        }
        replyPacket.verdict = verdict
        replyPacket.matchedRuleID = ruleID
        replyPacket.verdictReason = reason
        captureRing.append(replyPacket)
        totalFramesProcessed &+= 1
        totalSwitchRepliesGenerated &+= 1
    }

    private func forwardLateralFrameIfApplicable(
        senderVMID: VMID,
        dstMAC: MACAddress?,
        rawFrame: Data
    ) {
        guard let dstMAC, dstMAC != gatewayMAC else { return }

        if dstMAC.isBroadcast || dstMAC.isMulticast {
            for (peerVMID, var peerRecord) in portsByVMID where peerVMID != senderVMID {
                peerRecord.socketHandle?.sendDatagram(rawFrame)
                peerRecord.info.txFramesToGuest &+= 1
                peerRecord.info.txBytesToGuest &+= UInt64(rawFrame.count)
                portsByVMID[peerVMID] = peerRecord
            }
        } else if let targetEntry = fdbTable[dstMAC],
                  targetEntry.vmID != senderVMID,
                  var peerRecord = portsByVMID[targetEntry.vmID] {
            peerRecord.socketHandle?.sendDatagram(rawFrame)
            peerRecord.info.txFramesToGuest &+= 1
            peerRecord.info.txBytesToGuest &+= UInt64(rawFrame.count)
            portsByVMID[targetEntry.vmID] = peerRecord
        }
    }

    private func isIPOwnedByAnotherMAC(_ ip: IPv4Address, requester: MACAddress) -> Bool {
        let now = Date()
        for (mac, lease) in dhcpLeasesByMAC where mac != requester && lease.expiresAt > now {
            if lease.ipv4Address == ip {
                return true
            }
        }
        return false
    }

    private func allocateOrReuseLeaseIP(
        for clientMAC: MACAddress,
        vmID: VMID,
        requestedIP: IPv4Address?,
        hostname: String?,
        commitACK: Bool,
        leaseSeconds: UInt32
    ) -> IPv4Address? {
        let now = Date()
        let chosenIP: IPv4Address

        if let existing = dhcpLeasesByMAC[clientMAC],
           (requestedIP == nil || requestedIP == existing.ipv4Address) {
            chosenIP = existing.ipv4Address
        } else if let req = requestedIP,
                  dhcpPoolAddresses.contains(req),
                  !isIPOwnedByAnotherMAC(req, requester: clientMAC) {
            chosenIP = req
        } else {
            guard let available = dhcpPoolAddresses.first(where: { candidate in
                !isIPOwnedByAnotherMAC(candidate, requester: clientMAC)
            }) else {
                return nil
            }
            chosenIP = available
        }

        dhcpLeasesByMAC[clientMAC] = DHCPLeaseRecord(
            clientMAC: clientMAC,
            vmID: vmID,
            ipv4Address: chosenIP,
            subnetMask: subnetCIDR.netmask,
            routerIP: gatewayIP,
            hostname: hostname ?? dhcpLeasesByMAC[clientMAC]?.hostname,
            leaseSeconds: leaseSeconds,
            isCommittedACK: commitACK || (dhcpLeasesByMAC[clientMAC]?.isCommittedACK ?? false),
            issuedAt: now,
            expiresAt: now.addingTimeInterval(TimeInterval(leaseSeconds))
        )
        return chosenIP
    }

    private func resolveDomainToIPv4(_ rawDomain: String) -> IPv4Address {
        let clean = rawDomain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
        if let exact = staticDNSRecords[clean] {
            return exact
        }
        //Deterministic FNV-1a synthesis inside 198.18.x.y benchmark CIDR so repeated DNS queries map to stable IPs
        var hash: UInt64 = 1_469_598_103_934_665_603
        for b in clean.utf8 {
            hash ^= UInt64(b)
            hash &*= 1_099_511_628_211
        }
        let octet3 = UInt8((hash >> 8) & 0xFE)
        let octet4 = max(2, min(250, UInt8(hash & 0xFF)))
        return IPv4Address(a: 198, b: 18, c: octet3, d: octet4)
    }

    private static func computeDHCPLeasePool(
        subnet: IPv4CIDR,
        gatewayIP: IPv4Address
    ) -> [IPv4Address] {
        let net = subnet.networkAddress.rawHostOrder
        let bcast = subnet.broadcastAddress.rawHostOrder
        guard bcast > net + 2 else { return [] }

        // Default /24 or larger uses host offsets .10 ... .240 per AgentVM specification
        let firstCandidate: UInt32
        let lastCandidate: UInt32
        if subnet.prefixLength <= 24 {
            firstCandidate = net + 10
            lastCandidate = min(bcast - 1, net + 240)
        } else {
            firstCandidate = net + 2
            lastCandidate = bcast - 1
        }

        guard firstCandidate <= lastCandidate else { return [] }
        var pool: [IPv4Address] = []
        pool.reserveCapacity(Int(lastCandidate - firstCandidate + 1))
        for raw in firstCandidate...lastCandidate {
            let ip = IPv4Address(rawHostOrder: raw)
            if ip != gatewayIP {
                pool.append(ip)
            }
        }
        return pool
    }

    private static func defaultCuratedDNSRecords() -> [String: IPv4Address] {
        [
            "gateway.agentvm.internal": .switchGateway,
            "github.com": IPv4Address(a: 140, b: 82, c: 121, d: 4),
            "api.github.com": IPv4Address(a: 140, b: 82, c: 121, d: 6),
            "codeload.github.com": IPv4Address(a: 140, b: 82, c: 121, d: 10),
            "raw.githubusercontent.com": IPv4Address(a: 185, b: 199, c: 108, d: 133),
            "objects.githubusercontent.com": IPv4Address(a: 185, b: 199, c: 109, d: 133),
            "pypi.org": IPv4Address(a: 151, b: 101, c: 128, d: 223),
            "files.pypi.org": IPv4Address(a: 151, b: 101, c: 129, d: 223),
            "files.pythonhosted.org": IPv4Address(a: 151, b: 101, c: 130, d: 223),
            "registry.npmjs.org": IPv4Address(a: 104, b: 16, c: 24, d: 34),
            "crates.io": IPv4Address(a: 108, b: 138, c: 64, d: 100),
            "static.crates.io": IPv4Address(a: 108, b: 138, c: 64, d: 101),
            "api.anthropic.com": IPv4Address(a: 160, b: 79, c: 104, d: 25),
            "api.openai.com": IPv4Address(a: 162, b: 159, c: 140, d: 245)
        ]
    }

    private static func configureDatagramSocket(fd: Int32, nonBlocking: Bool) {
        var one: Int32 = 1
        _ = Darwin.setsockopt(
            fd,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &one,
            socklen_t(MemoryLayout<Int32>.size)
        )
        var bufSize: Int32 = 262_144
        _ = Darwin.setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVBUF,
            &bufSize,
            socklen_t(MemoryLayout<Int32>.size)
        )
        _ = Darwin.setsockopt(
            fd,
            SOL_SOCKET,
            SO_SNDBUF,
            &bufSize,
            socklen_t(MemoryLayout<Int32>.size)
        )
        if nonBlocking {
            let flags = Darwin.fcntl(fd, F_GETFL, 0)
            if flags >= 0 {
                _ = Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            }
        }
    }

    private static func nowMicroseconds() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970 * 1_000_000.0))
    }
}
