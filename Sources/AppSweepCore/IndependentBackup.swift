import Foundation

/// Dispatch only versioned, registered archive formats. Neither a path nor an
/// arbitrary reader can be supplied by a GUI, CLI argument or recovery document.
enum IndependentBackup {
    static func verifiedSnapshot(_ entry: RecoveryEntry, in directory: SafeDirectory) throws -> FileSnapshot {
        #if os(macOS)
        if entry.original.rule == DocumentVersionRule.name{return try DocumentHistoryTransaction.backup(entry,in:directory,home:SystemIdentity.home())}
        if entry.original.rule == PreferenceRecoveryRecord.rule { return try PreferenceTransaction.verifiedSnapshot(entry,in:directory,home:SystemIdentity.home()) }
        #endif
        if CacheArchive.supports(entry.original.rule) { return try CacheArchive.verifiedSnapshot(entry, in: directory) }
        return try CacheBackup.verifiedSnapshot(entry, in: directory)
    }
    static func materialize(_ entry: RecoveryEntry, from directory: SafeDirectory, into objects: SafeDirectory) throws -> FileSnapshot {
        guard entry.original.rule != PreferenceRecoveryRecord.rule,entry.original.rule != DocumentVersionRule.name else { throw SweepError.denied("偏好设置必须经原生服务恢复，不能重建为移动对象") }
        if CacheArchive.supports(entry.original.rule) { return try CacheArchive.materialize(entry, from: directory, into: objects) }
        return try CacheBackup.materialize(entry, from: directory, into: objects)
    }
    static func validatesReconstruction(_ snapshot: FileSnapshot, entry: RecoveryEntry, in directory: SafeDirectory) throws -> Bool {
        if CacheArchive.supports(entry.original.rule) { return try CacheArchive.validatesReconstruction(snapshot, entry: entry, in: directory) }
        return try CacheBackup.validatesReconstruction(snapshot, entry: entry, in: directory)
    }
}
