import Foundation
import CryptoKit

/// Presentation from inspected backup metadata, never cleanup authority.
public struct DeviceBackupDetails: Codable, Sendable, Equatable {
    public let groupKey: String
    public let deviceName: String
    public let date: Date
    public let encrypted: Bool

    init(identifier: String, deviceName: String, date: Date, encrypted: Bool) {
        groupKey = SHA256.hash(data:Data(identifier.lowercased().utf8)).map { String(format:"%02x",$0) }.joined()
        self.deviceName = deviceName; self.date = date; self.encrypted = encrypted
    }
    var wellFormed: Bool {
        groupKey.range(of:#"^[0-9a-f]{64}$"#,options:.regularExpression) != nil &&
        !deviceName.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty && deviceName.utf8.count <= 256 &&
        !deviceName.unicodeScalars.contains(where:CharacterSet.controlCharacters.contains) &&
        date.timeIntervalSince1970.isFinite && date.timeIntervalSince1970 > 0 && date <= Date().addingTimeInterval(86400)
    }
}

public enum DeviceBackupCatalog {
    public struct Group: Sendable, Identifiable {
        public let id: String
        public let deviceName: String?
        public let items: [Candidate]
        /// Latest among confirmed metadata only; not proof that every backup
        /// on the computer, another disk, or the device has been discovered.
        public let latestCandidateIDs: Set<UUID>
    }
    public static func groups(in candidates: [Candidate]) -> [Group] {
        var known: [String:[Candidate]] = [:], unknown: [Group] = []
        for item in candidates where item.category == .deviceBackup {
            if let details = item.deviceBackupDetails, details.wellFormed {
                known[details.groupKey,default:[]].append(item)
            } else {
                unknown.append(Group(id:"unconfirmed/" + item.id.uuidString,deviceName:nil,items:[item],latestCandidateIDs:[]))
            }
        }
        var groups = known.map { key, members -> Group in
            let ordered = members.sorted {
                let left = $0.deviceBackupDetails!.date, right = $1.deviceBackupDetails!.date
                if left != right { return left > right }
                if $0.path != $1.path { return $0.path < $1.path }
                return $0.id.uuidString < $1.id.uuidString
            }
            let latest = ordered[0].deviceBackupDetails!.date
            return Group(id:"device/" + key,deviceName:ordered[0].deviceBackupDetails!.deviceName,items:ordered,
                         latestCandidateIDs:Set(ordered.filter { $0.deviceBackupDetails!.date == latest }.map(\.id)))
        }
        groups.sort {
            let order = ($0.deviceName ?? "").localizedStandardCompare($1.deviceName ?? "")
            return order == .orderedSame ? $0.id < $1.id : order == .orderedAscending
        }
        return groups + unknown.sorted { $0.items[0].path < $1.items[0].path }
    }
}
