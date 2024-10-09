import struct
import avbtool
import generate_sign_script_for_vbmeta
import hashlib
from io import SEEK_SET
import os.path as op
from os import unlink
from shutil import copyfile
import zipfile


class vbmeta_pad:
    valid_android_ver = [8, 9, 10, 11, 13]
    valid_pad_size = [12288, 16384, 20480]

    def pad_8_12288(file: str):
        with open(file, "rb+") as f:
            b = f.read()
            f.truncate(0), f.seek(0, SEEK_SET)
            sha = hashlib.sha256(b).digest()
            f.write(
                b"\x44\x48\x54\x42\x01\x00\x00\x00"
                + sha
                + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00"
            )
            f.seek(512, SEEK_SET)
            f.write(b)

    def pad_9_16384(file: str):
        with open(file, "rb+") as f:
            b = f.read()
            f.truncate(0), f.seek(0, SEEK_SET)
            sha = hashlib.sha256(b).digest()
            f.write(b)
            f.seek(1048576 - 512, SEEK_SET)
            f.write(
                b"\x44\x48\x54\x42\x01\x00\x00\x00"
                + sha
                + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00"
            )
            f.truncate(1048576)

    def pad_10_20480(file: str):
        with open(file, "rb+") as f:
            b = f.read()
            f.truncate(0), f.seek(0, SEEK_SET)
            sha = hashlib.sha256(b).digest()
            f.write(b)
            f.seek(1048576 - 512, SEEK_SET)
            f.write(
                b"\x44\x48\x54\x42\x01\x00\x00\x00"
                + sha
                + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00"
            )
            f.truncate(1048576)

    def pad_11_20480(file: str):
        with open(file, "rb+") as f:
            b = f.read()
            f.truncate(0), f.seek(0, SEEK_SET)
            sha = hashlib.sha256(b).digest()
            f.write(b)
            f.seek(1048576 - 512, SEEK_SET)
            f.write(
                b"\x44\x48\x54\x42\x01\x00\x00\x00"
                + sha
                + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00"
            )
            f.seek(0xFFE3D, SEEK_SET)
            f.write(b"\x50")
            f.truncate(1048576)

    def pad_13_20480(file: str):
        with open(file, "rb+") as f:
            b = f.read()
            f.truncate(0), f.seek(0, SEEK_SET)
            sha = hashlib.sha256(b).digest()
            f.write(b)
            f.seek(1048576 - 512, SEEK_SET)
            f.write(
                b"\x44\x48\x54\x42\x01\x00\x00\x00"
                + sha
                + b"\xCC\xCC\xCC\xCC\xAA\xAA\xAA\xAA\x00\x50\x00\x00"
            )
            f.seek(0xFFE4D)
            f.write(b"\x50")
            f.seek(0xFFE50)
            f.write(b"\x60\x52")
            f.truncate(1048576)

    def pad(vbmeta_path: str, android_ver: int, pad_size: int):
        assert android_ver in vbmeta_pad.valid_android_ver, "Invalid android version"
        assert (
            pad_size in vbmeta_pad.valid_pad_size
        ), f"Invalid padding size: {pad_size}"

        if android_ver == 8:
            return vbmeta_pad.pad_8_12288(vbmeta_path)
        elif android_ver == 9:
            return vbmeta_pad.pad_9_16384(vbmeta_path)
        elif android_ver ==  10:
            return vbmeta_pad.pad_10_20480(vbmeta_path)
        elif android_ver == 11:
            return vbmeta_pad.pad_11_20480(vbmeta_path)
        elif android_ver ==  13:
            return vbmeta_pad.pad_13_20480(vbmeta_path)
        else:
            raise Exception("Invalid android version")


BOOT_MAGIC = b"ANDROID!"
BOOT_MAGIC_SIZE = 8
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512


class boot_img_hdr_meta(type):
    def __len__(cls):
        return struct.calcsize(
            f"<{BOOT_MAGIC_SIZE}s10I{BOOT_NAME_SIZE}s{BOOT_ARGS_SIZE}s8I"
        )


class boot_img_hdr(metaclass=boot_img_hdr_meta):
    def __init__(self, data: bytes) -> None:
        self.__structstr = f"<{BOOT_MAGIC_SIZE}s10I{BOOT_NAME_SIZE}s{BOOT_ARGS_SIZE}s8I"
        (
            self.magic,
            self.kernel_size,
            self.kernel_addr,
            self.ramdisk_size,
            self.ramdisk_addr,
            self.second_size,
            self.second_addr,
            self.tags_addr,
            self.page_size,
            self.unused1,
            self.unused2,
            self.name,
            self.cmdline,
            *self.id,
        ) = struct.unpack(self.__structstr, data)

    def __len__(self):
        return struct.calcsize(self.__structstr)

    def calc_boot_size(self) -> int:
        blk_sz = lambda page_size, n: ((n + page_size - 1) // page_size) * page_size

        size = (
            self.page_size
            + blk_sz(self.page_size, self.kernel_size)
            + blk_sz(self.page_size, self.ramdisk_size)
            + blk_sz(self.page_size, self.second_size)
        )
        if self.unused1 != 0:  # sprd extra
            size += blk_sz(self.page_size, self.unused1)
        return size


def dump_raw_image(image_path: str = "boot.img"):
    with open(image_path, "rb+") as f:
        offset = 0
        if struct.unpack("<I", f.read(4))[0] == 0x42544844:
            offset += 0x200

        f.seek(offset, SEEK_SET)
        hdr = boot_img_hdr(f.read(len(boot_img_hdr)))
        if hdr.magic != BOOT_MAGIC:
            raise Exception("Input image is not a boot image")

        boot_size = hdr.calc_boot_size()

        print("Dump boot image at offset: %d, size: %d" % (offset, boot_size))
        f.seek(offset, SEEK_SET)
        boot_raw = f.read(boot_size)

        f.truncate(0)
        f.seek(0, SEEK_SET)
        f.write(boot_raw)


def sign_image(
    image_path: str = "vbmeta.img",
    image_type: str = "boot",
    android_version: int = 8,
    sign_image_path: str = "boot.img",
    input_size: int = 36700160,
):
    output = "vbmeta-sign-custom.img"

    # Generate sign args
    print("Dumping...")
    dump_raw_image(sign_image_path)
    sign_args = generate_sign_script_for_vbmeta.generate_args(image_path)

    if op.exists(f"rsa4096_{image_type}_pub.bin"):
        unlink(f"rsa4096_{image_type}_pub.bin")

    if op.exists("rsa4096_custom_pub.bin"):
        copyfile("rsa4096_custom_pub.bin", f"rsa4096_{image_type}_pub.bin")

    # Sign new vbmeta
    print("Signing...")
    avbtool.AvbTool().run(sign_args)

    print("Padding...")
    padding_size = 0
    for index, current in enumerate(sign_args):
        if current == "--padding_size":
            padding_size = int(sign_args[index + 1])
    vbmeta_pad.pad(output, android_version, padding_size)

    if op.exists("vbmeta-sign-custom.img"):
        print("Vbmeta Signed!")
    else:
        return False  # Failed

    # Sign boot/recovery image
    sign_boot_args = (
        "avbtool",  # dummy arg
        "add_hash_footer",
        "--image",
        sign_image_path,
        "--partition_name",
        image_type,
        "--partition_size",
        f"{input_size}",
        "--key",
        "rsa4096_vbmeta.pem",
        "--algorithm",
        "SHA256_RSA4096",
    )
    print(f"Sign {image_type} image...")
    avbtool.AvbTool().run(sign_boot_args)
    print("Done!")


def pack_zip(vbmeta_image: str = "vbmeta-sign-custom.img", boot_image: str = "boot.img"):
    with zipfile.ZipFile(
        "./SignedImages.zip", "w", compression=zipfile.ZIP_DEFLATED
    ) as z:
        z.write(boot_image)
        z.write(vbmeta_image)
    print("Padked into SignedImages.zip")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="sign_image", description="Sign sprd boot/recovery image with custom key"
    )

    parser.add_argument(
        "-v,--vbmeta",
        default="vbmeta.img",
        type=str,
        dest="vbmeta",
        help="vbmeta image path",
    )
    parser.add_argument(
        "-t,--type",
        default="boot",
        type=str,
        dest="type",
        help="only recived boot/recovery",
    )
    parser.add_argument(
        "-a,--android_ver",
        default=8,
        type=int,
        dest="android_ver",
        help="only recive 8,9,10,11,13",
    )
    parser.add_argument(
        "-i,--image",
        default="boot.img",
        type=str,
        dest="image",
        help="image which will be signed. eg. like boot.img",
    )
    parser.add_argument(
        "-s,--size",
        default=36700160,
        type=int,
        dest="size",
        help="output signed image size",
    )

    args = parser.parse_args()

    sign_image(args.vbmeta, args.type, args.android_ver, args.image, args.size)
    pack_zip("vbmeta-sign-custom.img", "boot.img")
