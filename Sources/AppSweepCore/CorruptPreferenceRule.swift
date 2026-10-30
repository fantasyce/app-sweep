import Foundation
import CFSafety

/// Malformed bytes are preserved before any native reader can discard them.
/// This handles damaged files; valid native settings keep their service transaction.
enum CorruptPreferenceRule {
    static let name="corrupt-preference-file-v1"
    static func matches(path:String,home:String,identifier:String)->Bool {
        SystemCleanupScope.validIdentifier(identifier) && XcodeRule.canonical(path) && path == home + "/Library/Preferences/" + identifier + ".plist"
    }
    static func inspect(path:String,home:String,identifier:String)throws->PreferenceFileInspector.Inspection {
        guard matches(path:path,home:home,identifier:identifier) else{throw SweepError.denied("不是已确认的第三方应用偏好文件")}
        let value=try PreferenceFileInspector.inspect(path:path,home:home,identifier:identifier)
        guard value.status == .malformed else{throw SweepError.denied("文件没有被确认为格式损坏，保留")}
        _=try CacheBackup.metadata(value.snapshot)
        return value
    }
}
