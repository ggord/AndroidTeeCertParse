#include "zTeeCert.h"
#include "zLog.h"

int main() {

    std::vector<std::string> cert_path_list = std::vector<std::string>();
//    cert_path_list.push_back("C:\\Users\\lxz\\Desktop\\AndroidTee\\assests\\cert_k30pro.bin");
    cert_path_list.push_back("C:\\Users\\lxz\\Desktop\\AndroidTee\\assests\\cert_oneplus.bin");
//    cert_path_list.push_back("C:\\Users\\lxz\\Desktop\\AndroidTee\\assests\\cert_pixel4.bin");
//    cert_path_list.push_back("C:\\Users\\lxz\\Desktop\\AndroidTee\\assests\\cert_pixel6.bin");
//    cert_path_list.push_back("C:\\Users\\lxz\\Desktop\\AndroidTee\\assests\\cert_xiaomi6x.bin");

    for(std::string cert_path : cert_path_list){
        zTeeCert cert(cert_path);
        if (!cert.isValid()) {
            LOGE("[Native-TEE] 错误: 证书文件无效或解析失败");
            return cert.getParseResult();
        }

        LOGE("[Native-TEE] 证书解析成功！");
        const AttestationRecord* attestationRecord = cert.getX509Certificate()->getTBSCertificate()->getExtensions()->getTEEAttestationExtension()->getAttestationRecord();
        const AuthorizationList* softwareEnforced = attestationRecord->getSoftwareEnforced();
        const AuthorizationList* teeEnforced = attestationRecord->getTEEEnforced();
        
        // RootOfTrust 可能在 Software Enforced 或 TEE Enforced 中
        // 优先从 Software Enforced 获取，如果为空则从 TEE Enforced 获取
        const RootOfTrust* rootOfTrust = nullptr;
        if (softwareEnforced && !softwareEnforced->getRootOfTrust().verified_boot_key.empty()) {
            rootOfTrust = &softwareEnforced->getRootOfTrust();
        } else if (teeEnforced && !teeEnforced->getRootOfTrust().verified_boot_key.empty()) {
            rootOfTrust = &teeEnforced->getRootOfTrust();
        } else if (softwareEnforced) {
            rootOfTrust = &softwareEnforced->getRootOfTrust();
        } else if (teeEnforced) {
            rootOfTrust = &teeEnforced->getRootOfTrust();
        }

        LOGE("KeymasterSecurityLevel %d", (int)attestationRecord->getAttestationSecurityLevel());
        if (rootOfTrust) {
            LOGE("device_locked %d", rootOfTrust->device_locked);
            LOGE("verified_boot_key size: %zu", rootOfTrust->verified_boot_key.size());
            if (!rootOfTrust->verified_boot_key.empty()) {
                LOGE("verified_boot_key (前8字节): %02X %02X %02X %02X %02X %02X %02X %02X",
                     rootOfTrust->verified_boot_key[0], rootOfTrust->verified_boot_key[1],
                     rootOfTrust->verified_boot_key[2], rootOfTrust->verified_boot_key[3],
                     rootOfTrust->verified_boot_key[4], rootOfTrust->verified_boot_key[5],
                     rootOfTrust->verified_boot_key[6], rootOfTrust->verified_boot_key[7]);
            }
            LOGE("verified_boot_state %d", rootOfTrust->verified_boot_state);
        } else {
            LOGE("RootOfTrust: 未找到");
        }
        
        // OSVersion 通常在 Software Enforced 中
        if (softwareEnforced) {
            LOGE("OSVersion (Software Enforced): %d", softwareEnforced->getOSVersion());
            LOGE("OSPatchLevel (Software Enforced): %d", softwareEnforced->getOSPatchLevel());
            LOGE("BootPatchLevel (Software Enforced): %d", softwareEnforced->getBootPatchLevel());
        }
        if (teeEnforced) {
            LOGE("OSVersion (TEE Enforced): %d", teeEnforced->getOSVersion());
            LOGE("OSPatchLevel (TEE Enforced): %d", teeEnforced->getOSPatchLevel());
            LOGE("BootPatchLevel (TEE Enforced): %d", teeEnforced->getBootPatchLevel());
        }
        LOGE("\n======================\n");
    }

    return 0;
}
