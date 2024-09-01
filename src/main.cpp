#include <libpst/libpst.h>

#include <libpst_extension.h>
#include <libpst_internal.h>

#include <microsoft_pst/pst_crc.h>

#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

void printCRC(int crc)
{
    uint32_t pwd_crc = crc;
    std::uint32_t a1 = pwd_crc & 0xffU;
    std::uint32_t a2 = (pwd_crc >> 8U) & 0xffU;
    std::uint32_t a3 = (pwd_crc >> 16U) & 0xffU;
    std::uint32_t a4 = (pwd_crc >> 24U) & 0xffU;
    std::cout << "Password CRC32: " << std::hex << a1 << " " << a2 << " " << a3 << " " << a4 << std::endl;
}

template<typename T>
void printHex(const T &data)
{
    for(char c : data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint32_t)(uint8_t)c;
    }
    std::cout << std::endl;
}

void selftest()
{
    std::string data = "Hal";
    std::vector<char> data_vec{data.begin(), data.end()};
    std::string data_orig = data;
    pst_encrypt(0, data_vec.data(), data_vec.size(), 1);

    printHex(data_orig);
    printHex(data_vec);

    pst_decrypt(0, data_vec.data(), data_vec.size(), 1);
    printHex(data_vec);
    if(data_orig != std::string(data_vec.begin(), data_vec.end()))
    {
        std::cout << "Selftest failed encryption" << std::endl;
        exit(-1);
    }

    for(uint8_t c = 0; c < 0xff; c++)
    {
        char test[2];
        test[0] = c;
        pst_encrypt(0, test, 1, 1);
        pst_decrypt(0, test, 1, 1);
        if((char)c != test[0])
        {
            std::cout << "Encryption test failed." << std::endl;
            exit(-1);
        }
    }


    // CRC Test Hello World: 563085498 Hello: 838041247

    if(ComputeCRC(0, "Hello World", 11) != 563085498)
    {
        std::cout << std::dec << "Hello World: " << ComputeCRC(0, "Hello World", 11) << std::endl;
        exit(-1);
    }
    if(ComputeCRC(0, "Hello", 5) != 838041247)
    {
        std::cout << std::dec << "Hello: " << ComputeCRC(0, "Hello", 5) << std::endl;
        exit(-1);
    }

    if(ComputeCRC(0, "Hello\xff", 6) != 1300468262)
    {
        std::cout << "CRC selftest failed: " << 1300468262 << " != " << ComputeCRC(0, "Hello\xff", 6) << std::endl;
    }

    std::cout << "Selftest passed" << std::endl;
}

uint32_t printCurrentPasswordCRC(pst_file &file)
{
    auto * root = pst_parse_item(&file, file.d_head, nullptr);
    if(root == nullptr)
    {
        std::cout << "Failed to get root item." << std::endl;
        exit(-1);
    }

    if(root->message_store == nullptr)
    {
        std::cout << "Failed to get messagestore." << std::endl;
        exit(-1);
    }

    printCRC(root->message_store->pwd_chksum);

    return root->message_store->pwd_chksum;
}

int main(int argc, const char **argv)
{
    if(argc != 2)
    {
        std::cout << "Usage: pst_password_remove ./file.pst" << std::endl;
        exit(-1);
    }

    init_comp_enc_reverse();
    selftest();

    pst_file file;
    const char *file_name = argv[1];
    std::cout << "Trying to open: " << file_name << std::endl;
    std::string target_file(file_name);
    target_file += ".nopasswd";
    std::filesystem::remove(target_file);
    std::filesystem::copy(file_name, target_file);
    if(pst_open_rw(&file, target_file.c_str(), "UTF-32") == -1)
    {
        std::cout << "Failed to open pst file" << std::endl;
        exit(-1);
    }

    if(pst_load_index(&file)!=0)
    {
        std::cout << "Failed to load index." << std::endl;
    }

    uint32_t pwd_crc = printCurrentPasswordCRC(file);
    if(pwd_crc == 0)
    {
        std::cout << "No password set." << std::endl;
        exit(0);
    }

    pst_delete_passwd(&file, file.d_head);

    pwd_crc = printCurrentPasswordCRC(file);
    if(pwd_crc == 0)
    {
        std::cout << "Password removed successfully." << std::endl;
    }

    pst_close(&file);

    exit(0);
}
