(.spdxVersion | type == "string" and startswith("SPDX-")) and
(.documentNamespace | type == "string" and length > 0) and
(.packages | type == "array" and length > 0) and
(.documentDescribes | type == "array" and length > 0)
