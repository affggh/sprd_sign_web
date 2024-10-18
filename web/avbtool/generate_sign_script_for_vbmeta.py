import struct

AVB_MAGIC_LEN = 4
AVB_RELEASE_STRING_SIZE = 48


class AvbVBMetaImageHeaderMeta(type):
    def __len__(cls):
        return struct.calcsize(
            f"<{AVB_MAGIC_LEN}s2I2QI11Q2I{AVB_RELEASE_STRING_SIZE}s80s"
        )


class AvbVBMetaImageHeader(metaclass=AvbVBMetaImageHeaderMeta):
    def __init__(self, data: bytes) -> None:
        self.__structstr = f"<{AVB_MAGIC_LEN}s2I2QI11Q2I{AVB_RELEASE_STRING_SIZE}s80s"

        (
            self.magic,
            self.required_libavb_version_major,
            self.required_libavb_version_minor,
            self.authentication_data_block_size,
            self.auxiliary_data_block_size,
            self.algorithm_type,
            self.hash_offset,
            self.hash_size,
            self.signature_offset,
            self.signature_size,
            self.public_key_offset,
            self.public_key_size,
            self.public_key_metadata_offset,
            self.public_key_metadata_size,
            self.descriptors_offset,
            self.descriptors_size,
            self.rollback_index,
            self.flags,
            self.rollback_index_location,
            self.release_string,
            self.reserved,
        ) = struct.unpack(self.__structstr, data)

    def pack(self):
        return struct.pack(
            self.__structstr,
            self.magic,
            self.required_libavb_version_major,
            self.required_libavb_version_minor,
            self.authentication_data_block_size,
            self.auxiliary_data_block_size,
            self.algorithm_type,
            self.hash_offset,
            self.hash_size,
            self.signature_offset,
            self.signature_size,
            self.public_key_offset,
            self.public_key_size,
            self.public_key_metadata_offset,
            self.public_key_metadata_size,
            self.descriptors_offset,
            self.descriptors_size,
            self.rollback_index,
            self.flags,
            self.rollback_index_location,
            self.release_string,
            self.reserved,
        )

    def __len__(self):
        return struct.calcsize(self.__structstr)


class AvbChainPartitionDescriptorMeta(type):
    def __len__(cls):
        return struct.calcsize("<2Q4I60s")


class AvbChainPartitionDescriptor(metaclass=AvbChainPartitionDescriptorMeta):
    def __init__(self, data: bytes) -> None:
        self.__structstr = "<2Q4I60s"
        (
            self.tag,
            self.num_bytes_following,
            self.rollback_index_location,
            self.partition_name_len,
            self.public_key_len,
            self.flags,
            self.reserved,
        ) = struct.unpack(self.__structstr, data)

    def pack(self):
        return struct.pack(
            self.__structstr,
            self.tag,
            self.num_bytes_following,
            self.rollback_index_location,
            self.partition_name_len,
            self.public_key_len,
            self.flags,
            self.reserved,
        )

    def __len__(self):
        return struct.calcsize(self.__structstr)


def reverse_uint64(x: int) -> int:
    result = 0

    result |= (x & 0x00000000000000FF) << 56
    result |= (x & 0x000000000000FF00) << 40
    result |= (x & 0x0000000000FF0000) << 24
    result |= (x & 0x00000000FF000000) << 8
    result |= (x & 0x000000FF00000000) >> 8
    result |= (x & 0x0000FF0000000000) >> 24
    result |= (x & 0x00FF000000000000) >> 40
    result |= (x & 0xFF00000000000000) >> 56
    return result


def reverse_uint32(x: int) -> int:
    result = 0

    result |= (x & 0x000000FF) << 24
    result |= (x & 0x0000FF00) << 8
    result |= (x & 0x00FF0000) >> 8
    result |= (x & 0xFF000000) >> 24
    return result


def generate(meta_path: str) -> None:
    with open(meta_path, "rb") as file, open("sign_vbmeta.sh", "w") as fo:
        buffer = file.read()

        ptr = 0
        if struct.unpack("<I", buffer[0:4])[0] == 0x42544844:
            ptr += 0x200

        vbheader = AvbVBMetaImageHeader(buffer[ptr : ptr + len(AvbVBMetaImageHeader)])
        algorithm_type = reverse_uint32(vbheader.algorithm_type)
        rsa = 256 * (1 if algorithm_type < 4 else 2)
        algorithm = 1024 * pow(
            2, algorithm_type if algorithm_type < 3 else algorithm_type - 3
        )
        print(
            f"python avbtool make_vbmeta_image --key rsa{algorithm}_vbmeta.pem --algorithm SHA{rsa}_RSA{algorithm} \\",
            file=fo,
        )

        chainheader = AvbChainPartitionDescriptor(
            buffer[
                ptr
                + len(AvbVBMetaImageHeader)
                + reverse_uint64(vbheader.authentication_data_block_size) : ptr
                + len(AvbVBMetaImageHeader)
                + reverse_uint64(vbheader.authentication_data_block_size)
                + len(AvbChainPartitionDescriptor)
            ]
        )
        tag = reverse_uint64(chainheader.tag)

        off = (
            ptr
            + len(AvbVBMetaImageHeader)
            + reverse_uint64(vbheader.authentication_data_block_size)
            + len(AvbChainPartitionDescriptor)
        )
        while True:
            rollback_index_location = reverse_uint32(
                chainheader.rollback_index_location
            )
            partition_name_len = reverse_uint32(chainheader.partition_name_len)
            public_key_len = reverse_uint32(chainheader.public_key_len)

            name = buffer[off : off + partition_name_len]
            key_path = f"rsa{algorithm}_{name.decode()}_pub.bin"
            print(f"extract {key_path}")

            with open(key_path, "wb") as key_file:
                key_file.write(
                    buffer[
                        off
                        + partition_name_len : off
                        + partition_name_len
                        + public_key_len
                    ]
                )

            print(
                f"--chain_partition {name.decode()}:{rollback_index_location}:keys/{key_path} \\",
                file=fo,
            )

            off += (
                len(AvbChainPartitionDescriptor)
                + partition_name_len
                + public_key_len
                + 7
            ) & 0xFFFFFFF8
            chainheader = AvbChainPartitionDescriptor(
                buffer[off - len(AvbChainPartitionDescriptor) : off]
            )
            if tag != reverse_uint64(chainheader.tag):
                break

        padding = 0x1000
        if struct.unpack("<I", buffer[0:4])[0] == 0x42544844:
            padding = struct.unpack("<I", buffer[0x30 : 0x30 + 4])[0]
        elif struct.unpack("<I", buffer[0xFFE00 : 0xFFE00 + 4])[0] == 0x42544844:
            padding = struct.unpack("<I", buffer[0xFFE30 : 0xFFE30 + 4])[0]
        else:
            print('Warning: "DHTB" header not found.')

        print(f"--padding_size {padding} --output vbmeta-sign-custom.img", file=fo)
        print(f"padding_size: {padding}")


def generate_args(meta_path: str) -> tuple:
    args = []

    with open(meta_path, "rb") as file:
        buffer = file.read()

        ptr = 0
        if struct.unpack("<I", buffer[0:4])[0] == 0x42544844:
            ptr += 0x200

        vbheader = AvbVBMetaImageHeader(buffer[ptr : ptr + len(AvbVBMetaImageHeader)])
        algorithm_type = reverse_uint32(vbheader.algorithm_type)
        rsa = 256 * (1 if algorithm_type < 4 else 2)
        algorithm = 1024 * pow(
            2, algorithm_type if algorithm_type < 3 else algorithm_type - 3
        )
        # print(
        #    f"python avbtool make_vbmeta_image --key rsa{algorithm}_vbmeta.pem --algorithm SHA{rsa}_RSA{algorithm} \\",
        #    file=fo,
        # )
        args.extend(
            (
                "avbtool",  # dummy command skip argparse
                "make_vbmeta_image",
                "--key",
                f"rsa{algorithm}_vbmeta.pem",
                "--algorithm",
                f"SHA{rsa}_RSA{algorithm}",
            )
        )

        chainheader = AvbChainPartitionDescriptor(
            buffer[
                ptr
                + len(AvbVBMetaImageHeader)
                + reverse_uint64(vbheader.authentication_data_block_size) : ptr
                + len(AvbVBMetaImageHeader)
                + reverse_uint64(vbheader.authentication_data_block_size)
                + len(AvbChainPartitionDescriptor)
            ]
        )
        tag = reverse_uint64(chainheader.tag)

        off = (
            ptr
            + len(AvbVBMetaImageHeader)
            + reverse_uint64(vbheader.authentication_data_block_size)
            + len(AvbChainPartitionDescriptor)
        )
        while True:
            rollback_index_location = reverse_uint32(
                chainheader.rollback_index_location
            )
            partition_name_len = reverse_uint32(chainheader.partition_name_len)
            public_key_len = reverse_uint32(chainheader.public_key_len)

            name = buffer[off : off + partition_name_len]
            key_path = f"rsa{algorithm}_{name.decode()}_pub.bin"
            print(f"extract {key_path}")

            with open(key_path, "wb") as key_file:
                key_file.write(
                    buffer[
                        off
                        + partition_name_len : off
                        + partition_name_len
                        + public_key_len
                    ]
                )

            # print(
            #    f"--chain_partition {name.decode()}:{rollback_index_location}:keys/{key_path} \\",
            #    file=fo,
            # )
            args.extend(
                (
                    "--chain_partition",
                    f"{name.decode()}:{rollback_index_location}:{key_path}",
                )
            )

            off += (
                len(AvbChainPartitionDescriptor)
                + partition_name_len
                + public_key_len
                + 7
            ) & 0xFFFFFFF8
            chainheader = AvbChainPartitionDescriptor(
                buffer[off - len(AvbChainPartitionDescriptor) : off]
            )
            if tag != reverse_uint64(chainheader.tag):
                break

        padding = 0x1000
        if struct.unpack("<I", buffer[0:4])[0] == 0x42544844:
            padding = struct.unpack("<I", buffer[0x30 : 0x30 + 4])[0]
        elif struct.unpack("<I", buffer[0xFFE00 : 0xFFE00 + 4])[0] == 0x42544844:
            padding = struct.unpack("<I", buffer[0xFFE30 : 0xFFE30 + 4])[0]
        else:
            print('Warning: "DHTB" header not found.')

        # print(f"--padding_size {padding} --output vbmeta-sign-custom.img", file=fo)
        args.extend(
            ("--padding_size", f"{padding}", "--output", "vbmeta-sign-custom.img")
        )

        print(f"padding_size: {padding}")

        return args


if __name__ == "__main__":
    import sys

    def usage():
        print(f"{sys.argv[0]} <vbmeta.img>")
        sys.exit(1)

    if sys.argv.__len__() < 2:
        usage()
    else:
        generate(sys.argv[1])
