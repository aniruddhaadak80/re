import Foundation
let dict: NSDictionary = ["name": "RevLens", "count": NSNumber(value: 42), "tags": NSArray(array: ["re", "swift"]), "pi": NSNumber(value: 3.25), "data": NSData(bytes: [1,2,3,4] as [UInt8], length: 4), "when": NSDate(timeIntervalSinceReferenceDate: 1000.0), "url": NSURL(string: "https://example.com/a")!, "set": NSSet(array: ["x"]), "uuid": NSUUID(uuidString: "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")!, "null": NSNull()]
let a = NSKeyedArchiver(requiringSecureCoding: false)
a.outputFormat = .binary
a.encode(dict, forKey: NSKeyedArchiveRootObjectKey)
a.finishEncoding()
try! a.encodedData.write(to: URL(fileURLWithPath: "dict.keyedarchive"))
let b = NSKeyedArchiver(requiringSecureCoding: false); b.outputFormat = .xml
b.encode(NSArray(array: ["one", NSNumber(value: 2), NSArray(array: ["nested"])]), forKey: NSKeyedArchiveRootObjectKey); b.finishEncoding()
try! b.encodedData.write(to: URL(fileURLWithPath: "array-xml.keyedarchive"))
public struct Point { public var x: Int; public var y: Double; public func moved(by d: Int) -> Point { Point(x: x + d, y: y) } }
public class Shape<T> { public var items: [T] = []; public init() {}; public func add(_ t: T) { items.append(t) } }
print(Point(x: 1, y: 2).moved(by: 3), Shape<String>().items)
