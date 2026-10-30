#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class NamedApplicationRuleTests: XCTestCase {
    func testDifferentDisplayNameCannotHideARuntimeNamespaceConflict() throws {
        let f=try NativeAcceptanceTests.NativeFixture();defer{try? f.clean()}
        let path=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil) as? [String:Any])
        info["CFBundleName"]="Different"
        for namespace in ["Sublime Text","Sublime Text/Profile"] {
            info["CrProductDirName"]=namespace
            try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
            let peer=try AppInspector.inspect(f.app,verifySignature:false)
            for source in ["/Applications/Sublime Text.app",f.home + "/Recovery/isolated-owner"] {
                XCTAssertThrowsError(try NamedApplicationRule.verifyNamespace(identifier:"com.sublimetext.4",source:source,inventory:[peer]))
            }
        }
        info["CrProductDirName"]="Unrelated"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
        let unrelated=try AppInspector.inspect(f.app,verifySignature:false)
        XCTAssertNoThrow(try NamedApplicationRule.verifyNamespace(identifier:"com.sublimetext.4",source:"/Applications/Sublime Text.app",inventory:[unrelated]))
    }
    func testGodotEditorSelectionNeverIncludesGameDataOrTheWholeParent() {
        let home="/Users/example",root=home + "/Library/Application Support/Godot"
        for path in [root,root + "/app_userdata",root + "/app_userdata/Game",root + "/unknown-folder"] {
            XCTAssertFalse(NamedApplicationRule.matches(path,home:home,identifier:GodotCacheRule.identifier,cache:false))
        }
        XCTAssertTrue(NamedApplicationRule.matches(root + "/editor_settings-4.7.tres",home:home,identifier:GodotCacheRule.identifier,cache:false))
    }
    func testForgedPublisherAndLinksCannotAuthorizeNamedData() throws {
        let f=try NativeAcceptanceTests.NativeFixture();defer{try? f.clean()}
        XCTAssertThrowsError(try NamedApplicationRule.verifyPublisher(application:f.app,identifier:"com.sublimetext.4"))
        let root=f.home + "/Library/Application Support/Sublime Text",outside=f.home + "/keep.txt"
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        try Data("keep".utf8).write(to:URL(fileURLWithPath:outside))
        try FileManager.default.createSymbolicLink(atPath:root + "/link",withDestinationPath:outside)
        XCTAssertThrowsError(try NamedApplicationRule.verify(root,home:f.home,identifier:"com.sublimetext.4",cache:false))
        XCTAssertFalse(NamedApplicationRule.matches(root,home:f.home,identifier:"org.example.sublime",cache:false))
        XCTAssertEqual(try String(contentsOfFile:outside,encoding:.utf8),"keep")
    }
}
#endif
