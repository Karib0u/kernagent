"""Comprehensive tests for core SnapshotTools methods."""

from pathlib import Path

import pytest

from kernagent.snapshot.tools import SnapshotTools


@pytest.fixture
def snapshot():
    """Create SnapshotTools instance with test fixture."""
    archive = Path(__file__).parent / "fixtures" / "bifrose.snapshot"
    return SnapshotTools(archive)


class TestSearchFunctions:
    """Test search_functions() with various filter combinations."""

    def test_search_all_functions_no_filters(self, snapshot):
        """Search without filters should return functions up to limit."""
        result = snapshot.search_functions(limit=10)
        assert "results" in result
        assert "count" in result
        assert result["count"] > 0
        assert len(result["results"]) <= 10

    def test_search_by_name_pattern(self, snapshot):
        """Search by name pattern should filter results."""
        result = snapshot.search_functions(name_pattern="main", limit=50)
        assert "results" in result
        # All results should have "main" in the name (case-insensitive)
        for func in result["results"]:
            assert "main" in func["name"].lower()

    def test_search_by_min_complexity(self, snapshot):
        """Search by minimum complexity should filter results."""
        result = snapshot.search_functions(min_complexity=10, limit=50)
        assert "results" in result
        # All results should have complexity >= 10
        for func in result["results"]:
            complexity = func.get("metrics", {}).get("cyclomatic_complexity", 0)
            assert complexity >= 10

    def test_search_by_min_size(self, snapshot):
        """Search by minimum size should filter results."""
        result = snapshot.search_functions(min_size=100, limit=50)
        assert "results" in result
        # All results should have size >= 100
        for func in result["results"]:
            size = func.get("metrics", {}).get("size_bytes", 0)
            assert size >= 100

    def test_search_with_decomp_filter_true(self, snapshot):
        """Search with has_decomp=True should only return functions with decompilation."""
        result = snapshot.search_functions(has_decomp=True, limit=50)
        assert "results" in result
        # All results should have decomp_path
        for func in result["results"]:
            assert func.get("decomp_path") is not None

    def test_search_with_decomp_filter_false(self, snapshot):
        """Search with has_decomp=False should only return functions without decompilation."""
        result = snapshot.search_functions(has_decomp=False, limit=50)
        assert "results" in result
        # All results should NOT have decomp_path
        for func in result["results"]:
            assert func.get("decomp_path") is None

    def test_search_combined_filters(self, snapshot):
        """Search with multiple filters should apply all of them."""
        result = snapshot.search_functions(
            min_complexity=5, min_size=50, has_decomp=True, limit=20
        )
        assert "results" in result
        # All results should meet all criteria
        for func in result["results"]:
            complexity = func.get("metrics", {}).get("cyclomatic_complexity", 0)
            size = func.get("metrics", {}).get("size_bytes", 0)
            assert complexity >= 5
            assert size >= 50
            assert func.get("decomp_path") is not None

    def test_search_respects_limit(self, snapshot):
        """Search should respect the limit parameter."""
        result = snapshot.search_functions(limit=5)
        assert "results" in result
        assert len(result["results"]) <= 5
        assert result["count"] == len(result["results"])

    def test_search_includes_xref_counts(self, snapshot):
        """Search results should include xref counts."""
        result = snapshot.search_functions(limit=10)
        assert "results" in result
        if result["results"]:
            func = result["results"][0]
            assert "xrefs_in_count" in func
            assert "xrefs_out_count" in func
            assert isinstance(func["xrefs_in_count"], int)
            assert isinstance(func["xrefs_out_count"], int)


class TestSearchStrings:
    """Test search_strings() with various patterns and options."""

    def test_search_strings_basic(self, snapshot):
        """Basic string search should find matching strings."""
        # Search for a common pattern - most binaries have http or some common string
        result = snapshot.search_strings("http", limit=10)
        assert "results" in result
        assert "count" in result

    def test_search_strings_case_sensitive(self, snapshot):
        """Case-sensitive search should respect case."""
        result_insensitive = snapshot.search_strings("HTTP", case_sensitive=False, limit=50)
        result_sensitive = snapshot.search_strings("HTTP", case_sensitive=True, limit=50)

        assert "results" in result_insensitive
        assert "results" in result_sensitive

        # Case-insensitive should find more or equal results
        assert result_insensitive["count"] >= result_sensitive["count"]

    def test_search_strings_respects_limit(self, snapshot):
        """String search should respect limit parameter."""
        result = snapshot.search_strings("", limit=3)  # Empty pattern matches all
        assert "results" in result
        assert len(result["results"]) <= 3

    def test_search_strings_includes_xrefs(self, snapshot):
        """String results should include xref information."""
        result = snapshot.search_strings("", limit=5)
        if result["results"]:
            string_entry = result["results"][0]
            assert "address" in string_entry
            assert "value" in string_entry
            assert "xref_count" in string_entry
            assert "xref_functions" in string_entry

    def test_search_strings_truncates_long_values(self, snapshot):
        """Long string values should be truncated to 200 chars."""
        result = snapshot.search_strings("", limit=50)
        for string_entry in result["results"]:
            assert len(string_entry["value"]) <= 200

    def test_search_strings_no_match(self, snapshot):
        """Search with no matches should return empty results."""
        result = snapshot.search_strings("XYZZY_NONEXISTENT_STRING_12345", limit=50)
        assert "results" in result
        assert result["count"] == 0


class TestGetFunction:
    """Test get_function() by name and EA."""

    def test_get_function_by_name(self, snapshot):
        """Getting function by name should return function details."""
        # First, find a valid function name
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]

            result = snapshot.get_function(func_name)
            assert "error" not in result
            assert result["name"] == func_name
            assert "ea" in result
            assert "prototype" in result

    def test_get_function_by_ea(self, snapshot):
        """Getting function by EA should return function details."""
        # First, find a valid EA
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_ea = search_result["results"][0]["ea"]

            result = snapshot.get_function(func_ea)
            assert "error" not in result
            assert result["ea"] == func_ea
            assert "name" in result

    def test_get_function_not_found(self, snapshot):
        """Getting nonexistent function should return error."""
        result = snapshot.get_function("NONEXISTENT_FUNCTION_XYZ")
        assert "error" in result

    def test_get_function_truncates_long_insn_list(self, snapshot):
        """Functions with >50 instructions should be truncated."""
        # Find a function with many instructions
        search_result = snapshot.search_functions(min_size=500, limit=10)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]
            result = snapshot.get_function(func_name)

            if "insn" in result and len(result["insn"]) > 50:
                assert len(result["insn"]) == 51  # 50 + truncation note
                assert "note" in result["insn"][-1]

    def test_get_function_includes_metrics(self, snapshot):
        """Function details should include metrics."""
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]
            result = snapshot.get_function(func_name)

            if "metrics" in result:
                metrics = result["metrics"]
                assert isinstance(metrics, dict)


class TestReadDecompilation:
    """Test read_decompilation() for reading C code."""

    def test_read_decompilation_success(self, snapshot):
        """Reading existing decompilation should return code."""
        # Find a function with decompilation
        search_result = snapshot.search_functions(has_decomp=True, limit=1)
        if search_result["results"]:
            decomp_path = search_result["results"][0]["decomp_path"]

            result = snapshot.read_decompilation(decomp_path)
            assert "error" not in result
            assert "code" in result
            assert "path" in result
            assert "lines" in result
            assert result["path"] == decomp_path
            assert len(result["code"]) > 0
            assert result["lines"] > 0

    def test_read_decompilation_not_found(self, snapshot):
        """Reading nonexistent decompilation should return error."""
        result = snapshot.read_decompilation("decomp/nonexistent_file.c")
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_read_decompilation_path_traversal(self, snapshot):
        """Reading with path traversal should be rejected."""
        result = snapshot.read_decompilation("../../../etc/passwd")
        assert "error" in result


class TestSearchImportsExports:
    """Test search_imports_exports() with various filters."""

    def test_search_all_imports_exports(self, snapshot):
        """Search without filters should return all imports and exports."""
        result = snapshot.search_imports_exports(limit=100)
        assert "results" in result
        assert "count" in result

    def test_search_only_imports(self, snapshot):
        """Search with import_type='import' should return only imports."""
        result = snapshot.search_imports_exports(import_type="import", limit=100)
        assert "results" in result
        # Results should be imports (though we can't easily verify without checking the data)

    def test_search_only_exports(self, snapshot):
        """Search with import_type='export' should return only exports."""
        result = snapshot.search_imports_exports(import_type="export", limit=100)
        assert "results" in result

    def test_search_by_name_pattern(self, snapshot):
        """Search by name pattern should filter results."""
        # Try a common API name pattern
        result = snapshot.search_imports_exports(name_pattern="create", limit=50)
        assert "results" in result
        # All results should have "create" in the name
        for entry in result["results"]:
            assert "create" in entry.get("name", "").lower()

    def test_search_by_library(self, snapshot):
        """Search by library should filter results."""
        # First get all imports to find a library name
        all_imports = snapshot.search_imports_exports(import_type="import", limit=100)
        if all_imports["results"]:
            # Get first library name
            library = all_imports["results"][0].get("library")
            if library:
                result = snapshot.search_imports_exports(library=library, limit=50)
                assert "results" in result
                # All results should be from this library
                for entry in result["results"]:
                    assert library.lower() in entry.get("library", "").lower()

    def test_search_respects_limit(self, snapshot):
        """Import/export search should respect limit."""
        result = snapshot.search_imports_exports(limit=5)
        assert "results" in result
        assert len(result["results"]) <= 5

    def test_search_combined_filters(self, snapshot):
        """Search with multiple filters should apply all."""
        result = snapshot.search_imports_exports(
            name_pattern="get", import_type="import", limit=20
        )
        assert "results" in result
        for entry in result["results"]:
            assert "get" in entry.get("name", "").lower()


class TestGetXrefs:
    """Test get_xrefs() with various directions and types."""

    def test_get_xrefs_basic(self, snapshot):
        """Basic xref query should return cross-references."""
        # Find a function first
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]

            result = snapshot.get_xrefs(func_name, direction="both", limit=50)

            # Should have resolved target
            if "error" not in result:
                assert "resolved_target" in result
                assert "xrefs" in result
                assert result["resolved_target"]["name"] == func_name

    def test_get_xrefs_direction_to(self, snapshot):
        """Getting xrefs TO should only show incoming references."""
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]

            result = snapshot.get_xrefs(func_name, direction="to", limit=50)
            if "error" not in result and result["xrefs"]:
                # All xrefs should be TO direction
                for xref in result["xrefs"]:
                    assert xref.get("direction") == "to"

    def test_get_xrefs_direction_from(self, snapshot):
        """Getting xrefs FROM should only show outgoing references."""
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]

            result = snapshot.get_xrefs(func_name, direction="from", limit=50)
            if "error" not in result and result["xrefs"]:
                # All xrefs should be FROM direction
                for xref in result["xrefs"]:
                    assert xref.get("direction") == "from"

    def test_get_xrefs_type_code(self, snapshot):
        """Getting xrefs with type='code' should filter to code refs."""
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]

            result = snapshot.get_xrefs(func_name, xref_type="code", limit=50)
            if "error" not in result and result["xrefs"]:
                # All xrefs should be code type
                for xref in result["xrefs"]:
                    assert xref.get("kind") in ["code", None]

    def test_get_xrefs_type_data(self, snapshot):
        """Getting xrefs with type='data' should filter to data refs."""
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]

            result = snapshot.get_xrefs(func_name, xref_type="data", limit=50)
            # Should not error even if no data refs exist
            assert "xrefs" in result or "error" in result

    def test_get_xrefs_invalid_direction(self, snapshot):
        """Invalid direction should return error."""
        result = snapshot.get_xrefs("main", direction="sideways")
        assert "error" in result

    def test_get_xrefs_invalid_type(self, snapshot):
        """Invalid xref_type should return error."""
        result = snapshot.get_xrefs("main", xref_type="invalid")
        assert "error" in result

    def test_get_xrefs_nonexistent_target(self, snapshot):
        """Nonexistent target should return error."""
        result = snapshot.get_xrefs("NONEXISTENT_FUNCTION_XYZ_12345")
        assert "error" in result

    def test_get_xrefs_respects_limit(self, snapshot):
        """Xref query should respect limit parameter."""
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_name = search_result["results"][0]["name"]

            result = snapshot.get_xrefs(func_name, limit=3)
            if "error" not in result:
                assert len(result["xrefs"]) <= 3

    def test_get_xrefs_by_address(self, snapshot):
        """Getting xrefs by hex address should work."""
        search_result = snapshot.search_functions(limit=1)
        if search_result["results"]:
            func_ea = search_result["results"][0]["ea"]

            result = snapshot.get_xrefs(func_ea, limit=50)
            if "error" not in result:
                assert "resolved_target" in result
                assert result["resolved_target"]["ea"] is not None


class TestErrorHandling:
    """Test error handling in SnapshotTools."""

    def test_invalid_snapshot_root(self):
        """Initializing with invalid root should raise error."""
        with pytest.raises(FileNotFoundError):
            SnapshotTools(Path("/nonexistent/path/12345"))

    def test_snapshot_root_not_directory(self, tmp_path):
        """Initializing with file instead of directory should raise error."""
        file_path = tmp_path / "not_a_dir"
        file_path.touch()

        with pytest.raises(ValueError, match="must be a directory"):
            SnapshotTools(file_path)

    def test_read_json_missing_file(self, snapshot):
        """Reading missing JSON should return error."""
        result = snapshot.read_json("nonexistent.json")
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_search_data_invalid_limit(self, snapshot):
        """search_data with invalid limit should return error."""
        result = snapshot.search_data(limit=0)
        assert "error" in result

    def test_search_data_negative_offset(self, snapshot):
        """search_data with negative offset should return error."""
        result = snapshot.search_data(offset=-1)
        assert "error" in result


class TestNormalizationHelpers:
    """Test address normalization helpers."""

    def test_normalize_ea_hex_string(self):
        """Hex strings should be normalized correctly."""
        assert SnapshotTools._normalize_ea("0x1234") == "1234"
        assert SnapshotTools._normalize_ea("0x0") == "0"
        assert SnapshotTools._normalize_ea("ABCD") == "ABCD"

    def test_normalize_ea_integer(self):
        """Integers should be converted to hex."""
        assert SnapshotTools._normalize_ea(0x1234) == "1234"
        assert SnapshotTools._normalize_ea(255) == "FF"
        assert SnapshotTools._normalize_ea(0) == "0"

    def test_normalize_ea_invalid(self):
        """Invalid addresses should return None."""
        assert SnapshotTools._normalize_ea(None) is None
        assert SnapshotTools._normalize_ea("") is None
        assert SnapshotTools._normalize_ea("invalid") is None

    def test_ea_to_int(self):
        """EA to int conversion should work."""
        assert SnapshotTools._ea_to_int("0x1234") == 0x1234
        assert SnapshotTools._ea_to_int(0x1234) == 0x1234
        assert SnapshotTools._ea_to_int("ABCD") == 0xABCD
        assert SnapshotTools._ea_to_int(None) is None
