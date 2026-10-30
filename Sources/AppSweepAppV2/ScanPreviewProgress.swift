import AppSweepCore
import Foundation

/// Presentation only: progress buffering must not lose an already completed
/// scope just because a newer heartbeat has no new report attached.
final class ScanPreviewProgress: @unchecked Sendable {
    private let lock=NSLock()
    private var reports:[String:ScanReport]=[:]
    func merging(_ update:ScanProgress) -> ScanProgress {
        lock.lock();defer{lock.unlock()}
        reports.merge(update.completedReports){_,latest in latest}
        return .init(stage:update.stage,detail:update.detail,discoveredCount:update.discoveredCount,completedReports:reports)
    }
}
