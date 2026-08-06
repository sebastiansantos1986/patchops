import Foundation

@main
struct InventoryProbe {
    static func main() throws {
        let snapshot = InventoryCollector().collect()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        FileHandle.standardOutput.write(try encoder.encode(snapshot))
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
