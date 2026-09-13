#!/usr/bin/env -S PYTHONPATH=../../../tools/extract-utils python3
#
# SPDX-FileCopyrightText: 2024 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

import hashlib
from pathlib import Path

from extract_utils.main import (
    ExtractUtils,
    ExtractUtilsModule,
)
from extract_utils.fixups_blob import (
    blob_fixup,
    blob_fixups_user_type,
)

namespace_imports = [
    'hardware/oneplus',
    'hardware/qcom-caf/sdm660',
    'hardware/qcom-caf/msm8998',
    'vendor/oneplus/msm8998-common',
]


def fixup_camera(ctx, file, file_path, *args, **kwargs):
    path = Path(file_path)
    data = path.read_bytes()
    input_hash = '3182a0192eeacd0be37dddaa3f27b1e994ea2836704c67422d0e1113b4b74a01'
    output_hash = '1e50afa573e28cd398700b3783c8b64d315c08048c45e4c7aebc16f769c91c26'
    current_hash = hashlib.sha256(data).hexdigest()
    if current_hash == output_hash:
        return
    if current_hash != input_hash:
        raise ValueError(f'Unexpected camera.msm8998.so hash: {current_hash}')
    replacements = (
        (
            0xA0F9C,
            bytes.fromhex('c168d0e90d20cde90320'),
            bytes.fromhex('c168d0e91220cde90320'),
        ),
        (
            0xA0FC6,
            bytes.fromhex('3168089a0026496bcbe90421'),
            bytes.fromhex('3168089a0026896ccbe90421'),
        ),
    )
    for offset, old, new in replacements:
        if (
            data.count(old) != 1
            or data.find(old) != offset
            or data.count(new) != 0
        ):
            raise ValueError('Unexpected camera.msm8998.so patch pattern')
        data = data.replace(old, new)
    if hashlib.sha256(data).hexdigest() != output_hash:
        raise ValueError('camera.msm8998.so output hash mismatch')
    path.write_bytes(data)


# This table needs scalar 0x7c entries rather than an i8-splat sentinel.
def fixup_iface_scalar_sentinel(ctx, file, file_path, *args, **kwargs):
    path = Path(file_path)
    data = path.read_bytes()
    input_hash = 'e3e7ce4302be252242b2ea58967c9fb9b5d6033fc551e0d64b2b337d90c13154'
    output_hash = '6da4d769702a0916693085dd3c07e1afca9473596a7c9640f7bc7356f7a75942'
    context_offset = 0x2FD4E
    instruction_offset = 0x2FD5E
    old_context = bytes.fromhex(
        '00f5c03040f6845100f5ac700ef0aaefc7ef5c0e0aa8002e40f90d0a40f9cf0a'
        '19d0bbf1000f16d0306c08282cd3dff8'
    )
    old_instruction = bytes.fromhex('c7ef5c0e')
    new_instruction = bytes.fromhex('c7ef5c00')
    new_context = old_context.replace(old_instruction, new_instruction)
    current_hash = hashlib.sha256(data).hexdigest()
    if current_hash == output_hash:
        return
    if current_hash != input_hash:
        raise ValueError(
            f'Unexpected libmmcamera2_iface_modules.so hash: {current_hash}'
        )
    if (
        data.count(old_context) != 1
        or data.find(old_context) != context_offset
        or data.count(new_context) != 0
    ):
        raise ValueError('Unexpected IFACE scalar-sentinel context')
    if data[instruction_offset:instruction_offset + len(old_instruction)] != old_instruction:
        raise ValueError('Unexpected IFACE scalar-sentinel instruction')
    data = (
        data[:instruction_offset]
        + new_instruction
        + data[instruction_offset + len(old_instruction):]
    )
    if hashlib.sha256(data).hexdigest() != output_hash:
        raise ValueError('libmmcamera2_iface_modules.so output hash mismatch')
    path.write_bytes(data)


blob_fixups: blob_fixups_user_type = {
    'vendor/lib/libSonyIMX350PdafLibrary.so': blob_fixup()
        .replace_needed('libstdc++.so', 'libstdc++_vendor.so'),
    'vendor/lib/hw/camera.msm8998.so': blob_fixup().call(
        fixup_camera, need_tmp_dir=False
    ),
    'vendor/lib/libmmcamera2_iface_modules.so': blob_fixup().call(
        fixup_iface_scalar_sentinel, need_tmp_dir=False
    ),
}  # fmt: skip

module = ExtractUtilsModule(
    'cheeseburger',
    'oneplus',
    blob_fixups=blob_fixups,
    namespace_imports=namespace_imports,
    add_firmware_proprietary_file=True,
)

if __name__ == '__main__':
    utils = ExtractUtils.device_with_common(
        module, 'msm8998-common', module.vendor
    )
    utils.run()
