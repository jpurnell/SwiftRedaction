import Foundation

/// The byte patterns that count as a secret being present: the value as written, and the encodings a logger or an
/// HTTP client commonly applies before writing it.
enum SecretForms {
    /// A form of a secret: its name and the bytes to look for.
    struct Form: Sendable {
        let name: String
        let bytes: [UInt8]
    }

    /// The shortest encoded form that is searched for, so a one-byte secret does not match every file.
    static let minimumEncodedLength = 4

    /// Every form of `value` that is distinct from the others, raw first.
    static func forms(of value: String) -> [Form] {
        let raw = Array(value.utf8)
        guard !raw.isEmpty else { return [] }
        var forms = [Form(name: "raw", bytes: raw)]
        forms.append(Form(name: "utf16le", bytes: value.utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] }))
        forms.append(Form(name: "utf16be", bytes: value.utf16.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] }))
        forms.append(contentsOf: base64Forms(of: raw))
        forms.append(contentsOf: percentForms(of: raw))
        forms.append(Form(name: "hex", bytes: Array(hex(raw, uppercase: false).utf8)))
        forms.append(Form(name: "HEX", bytes: Array(hex(raw, uppercase: true).utf8)))
        var seen = Set<[UInt8]>()
        return forms.filter { form in
            (form.name == "raw" || form.bytes.count >= minimumEncodedLength) && seen.insert(form.bytes).inserted
        }
    }

    private static func hex(_ bytes: [UInt8], uppercase: Bool) -> String {
        bytes.map { byte in
            let digits = String(byte, radix: 16, uppercase: uppercase)
            return digits.count == 1 ? "0" + digits : digits
        }.joined()
    }

    /// Base64 (standard and URL-safe, padded and not) at each of the three alignments a secret can have inside a
    /// longer encoded blob. For the shifted alignments the characters that depend on the neighbouring bytes are dropped.
    private static func base64Forms(of raw: [UInt8]) -> [Form] {
        var forms: [Form] = []
        for shift in 0..<3 {
            let padded = [UInt8](repeating: 0, count: shift) + raw
            var encoded = Data(padded).base64EncodedString()
            while encoded.hasSuffix("=") { encoded.removeLast() }
            let leading = [0, 2, 3][shift]
            let trailing = (padded.count % 3 == 0) ? 0 : 1
            guard encoded.count > leading + trailing else { continue }
            let stable = String(encoded.dropFirst(leading).dropLast(trailing))
            let urlSafe = stable.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            let name = shift == 0 ? "base64" : "base64 (offset \(shift))"
            forms.append(Form(name: name, bytes: Array(stable.utf8)))
            forms.append(Form(name: shift == 0 ? "base64url" : "base64url (offset \(shift))", bytes: Array(urlSafe.utf8)))
        }
        return forms
    }

    /// The value with every byte outside RFC 3986's unreserved set written as `%XX`, and with every byte written so.
    private static func percentForms(of raw: [UInt8]) -> [Form] {
        let unreserved = Set(Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~".utf8))
        func escape(_ byte: UInt8) -> String {
            let digits = String(byte, radix: 16, uppercase: true)
            return "%" + (digits.count == 1 ? "0" + digits : digits)
        }
        let minimal = raw.map { unreserved.contains($0) ? String(UnicodeScalar($0)) : escape($0) }.joined()
        let everything = raw.map(escape).joined()
        return [Form(name: "percent", bytes: Array(minimal.utf8)), Form(name: "percent (every byte)", bytes: Array(everything.utf8))]
    }

    /// Whether `needle` occurs in `haystack`.
    static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard let first = needle.first, needle.count <= haystack.count else { return false }
        var start = 0
        let last = haystack.count - needle.count
        while start <= last {
            if haystack[start] == first, haystack[start..<start + needle.count].elementsEqual(needle) { return true }
            start += 1
        }
        return false
    }
}
