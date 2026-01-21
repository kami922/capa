# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Test for Issue #2794: SegmentationViolation handling in loader.

This test verifies that malformed ELF files with invalid relocations
are handled gracefully instead of crashing with a segmentation fault.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import envi.exc

from capa.loader import CorruptFile, get_workspace
from capa.features.common import FORMAT_ELF


def test_segmentation_violation_handling():
    """
    Test that SegmentationViolation from vivisect is caught and
    converted to CorruptFile exception.

    This addresses issue #2794 where malformed ELF files with
    invalid relocations cause vivisect to raise SegmentationViolation
    during relocation processing.
    """
    # Create a fake path (doesn't need to exist for mock test)
    fake_path = Path("/tmp/fake_malformed.elf")

    with patch("viv_utils.getWorkspace") as mock_workspace:
        # Simulate vivisect raising SegmentationViolation on malformed ELF
        mock_workspace.side_effect = envi.exc.SegmentationViolation(
            0x30A4B8BD60, "Bad Memory Read (invalid memory address): 0x30a4b8bd60: 0x8"
        )

        # The fix should convert SegmentationViolation to CorruptFile
        with pytest.raises(CorruptFile) as exc_info:
            get_workspace(
                fake_path,
                FORMAT_ELF,
                [],  # empty signature paths
            )

        # Verify the exception message is helpful
        error_message = str(exc_info.value)
        assert "Invalid memory access" in error_message or "Malformed binary" in error_message


def test_normal_elf_still_works():
    """
    Verify that normal ELF files still work after the SegmentationViolation fix.
    This ensures we didn't break existing functionality.
    """
    fake_path = Path("/tmp/normal.elf")

    with patch("viv_utils.getWorkspace") as mock_workspace:
        with patch("viv_utils.flirt.register_flirt_signature_analyzers"):
            # Simulate successful workspace creation
            mock_vw = MagicMock()
            mock_workspace.return_value = mock_vw

            # This should work normally
            result = get_workspace(fake_path, FORMAT_ELF, [])

            assert result is mock_vw
            mock_workspace.assert_called_once()
