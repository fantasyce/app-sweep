import XCTest
@testable import AppSweepCore
#if os(macOS)
import Darwin
#else
import Glibc
#endif

final class ProcessTests: XCTestCase {
    func testDescriptorInputUsesOpenedFileAfterItsPathIsReplaced() throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        defer { try? FileManager.default.removeItem(at:root) }
        let path=root.appendingPathComponent("input")
        try Data("verified input\n".utf8).write(to:path)
        let fd=open(path.path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC)
        guard fd>=3 else { throw SweepError.filesystem("Owned input descriptor unavailable") };defer { close(fd) }
        try FileManager.default.moveItem(at:path,to:root.appendingPathComponent("original"))
        try Data("untrusted replacement\n".utf8).write(to:path)
        let output=try BoundedProcess.capture("/bin/cat",arguments:[],timeout:1,mergeStderr:false,inputFD:fd)
        XCTAssertEqual(output.status,0);XCTAssertEqual(output.text,"verified input\n")
        XCTAssertThrowsError(try BoundedProcess.capture("/bin/cat",arguments:[],timeout:1,mergeStderr:false,inputFD:0))
        XCTAssertThrowsError(try BoundedProcess.capture("/bin/cat",arguments:[],timeout:1,mergeStderr:false,inputFD:-2))
    }
    func testTimeoutTerminatesOnlyItsOwnedProcessGroup() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let pidFile = root.appendingPathComponent("child.pid")
        let started = Date()
        XCTAssertThrowsError(try BoundedProcess.run("/bin/sh", arguments: ["-c", "sleep 60 & echo $! > \"$1\"; wait", "fixture", pidFile.path], timeout: 0.15))
        XCTAssertLessThan(Date().timeIntervalSince(started), 2)
        let child = try XCTUnwrap(Int32(String(contentsOf: pidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)))
        defer { _ = kill(child, SIGKILL) } // Exact task-created child, even while watching the RED case.
        Thread.sleep(forTimeInterval: 0.1)
        let state = try? BoundedProcess.run("/bin/ps", arguments: ["-p", String(child), "-o", "stat="], timeout: 1)
        XCTAssertTrue(state == nil || state!.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("Z"), "An owned descendant survived the timeout")
    }
    func testNonzeroExitIsUnknown() {
        XCTAssertThrowsError(try BoundedProcess.run("/bin/sh", arguments: ["-c", "exit 7"], timeout: 1))
    }
    func testTruncatedOutputIsUnknown() {
        XCTAssertThrowsError(try BoundedProcess.run("/bin/sh", arguments: ["-c", "yes x | head -c 2200000"], timeout: 1))
    }
    func testExpectedNonzeroExitPreservesDiagnosticOutput() throws {
        let output = try BoundedProcess.capture("/bin/sh", arguments: ["-c", "echo denied >&2; exit 5"], timeout: 1, mergeStderr: true)
        XCTAssertEqual(output.status, 5)
        XCTAssertEqual(output.text, "denied\n")
    }
    func testEmptyExpectedExitIsDifferentFromSpawnFailure() throws {
        let output = try BoundedProcess.capture("/bin/sh", arguments: ["-c", "exit 1"], timeout: 1, mergeStderr: true)
        XCTAssertEqual(output.status, 1); XCTAssertTrue(output.text.isEmpty)
        XCTAssertThrowsError(try BoundedProcess.capture("/absent", arguments: [], timeout: 1, mergeStderr: true))
    }

    func testClosedParentStdoutCannotHideChildOutput() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let sourceRoot = ProcessInfo.processInfo.environment["APP_SWEEP_SOURCE_ROOT"] ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        let source = root.appendingPathComponent("probe.c"), binary = root.appendingPathComponent("probe"), result = root.appendingPathComponent("result")
        let code = """
        #include "CFSafety.h"
        #include <unistd.h>
        #include <fcntl.h>
        int main(int argc,char **argv){
          if(argc!=2)return 2;
          int fd=open(argv[1],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
          if(fd<0)return 3;
          close(STDOUT_FILENO);
          char *args[]={"/bin/echo","captured",0};char data[1024];size_t count=0;int status=-1;
          int r=as_run_process("/bin/echo",args,data,sizeof(data),1000,&count,1,&status);
          write(fd,data,count);close(fd);return r==0&&status==0?0:7;
        }
        """
        try code.write(to: source, atomically: true, encoding: .utf8)
        let bundledClang = "/opt/swift/usr/bin/clang"
        let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? (FileManager.default.isExecutableFile(atPath: bundledClang) ? bundledClang : "/usr/bin/clang")
        var args = ["-I", sourceRoot + "/Sources/CFSafety/include", sourceRoot + "/Sources/CFSafety/process.c", source.path, "-o", binary.path]
        if let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] { args += ["-isysroot", sdk] }
        let compiled = try BoundedProcess.capture(clang, arguments: args, timeout: 30, mergeStderr: true)
        XCTAssertEqual(compiled.status, 0, compiled.text)
        guard compiled.status == 0 else { return }
        let probe = try BoundedProcess.capture(binary.path, arguments: [result.path], timeout: 3, mergeStderr: true)
        XCTAssertEqual(probe.status, 0)
        XCTAssertEqual(try String(contentsOf: result, encoding: .utf8), "captured\n")
    }

}
