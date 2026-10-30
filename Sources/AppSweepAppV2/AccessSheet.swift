import SwiftUI

@MainActor
struct AccessSheet: View {
    let rescan: () -> Void
    var body: some View {
        AccessOnboardingView(continueToWorkspace: rescan)
            .frame(width: 720, height: 620)
    }
}
