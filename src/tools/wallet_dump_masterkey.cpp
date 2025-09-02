// Minimal tool: wallet_dump_masterkey.cpp
// Place in bitcoin/src/tools/ and build against your bitcoin build.
// WARNING: handle copied wallet.dat only. DO NOT use on original until tested.

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <chainparams.h>
#include <fs.h>
#include <init.h>
#include <key.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <util/argparser.h>
#include <util/system.h>
#include <util/translation.h>
#include <wallet/crypter.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/loader.h>

using namespace std;

static void SetupEnvironmentAndParams(const std::string& datadir) {
    // Minimal environment setup
    fs::path dir(datadir);
    gArgs.ForceSetArg("-datadir", dir.string());
    SelectParams(CBaseChainParams::REGTEST);
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "Usage: wallet_dump_masterkey <path-to-wallet-dat-dir> <64-hex-masterkey>\n"
                  << "Example: wallet_dump_masterkey C:\\btc-testdir 0123...64hex\n";
        return 1;
    }

    std::string datadir = argv[1];
    std::string hex = argv[2];

    if (hex.size() != 64) {
        std::cerr << "Master key must be 64 hex chars (32 bytes)\n";
        return 1;
    }

    // Basic init (logger, ECC)
    ECC_Start();
    SetupEnvironmentAndParams(datadir);

    // Initialize wallet environment (no network)
    ArgsManager& args = gArgs;
    args.SoftSetBoolArg("-fallbackfee", true); // avoid asserts
    // Minimal app init for wallet loader:
    util::Ref context{nullptr};

    // Construct WalletLoader and load wallet from datadir
    WalletLocation location(fs::path(datadir) / "wallet.dat");
    WalletContext wallet_context;
    bilingual_str error;
    std::unique_ptr<CWallet> wallet;

    // This uses wallet loader API; CreateWalletFromFile expects a wallet name (filename)
    // We will call LoadWallet to get an instance. This follows the loader flow.
    // Note: code may need small tweaks based on exact Core version (field names).
    std::vector<std::unique_ptr<interfaces::Wallet>> dummy;
    std::string wallet_name = "wallet.dat";

    // Construct wallet via LoadWallet (loader utilities present in modern Core)
    bool load_ok = false;
    try {
        // Use the low-level wallet DB to open the wallet
        WalletDatabase wallet_database(location.GetName(), /*create=*/false, /*wallet=*/nullptr);
        // Create CWallet instance (makes an unlocked wallet object in memory)
        wallet.reset(new CWallet(&wallet_context, wallet_database));
        wallet->LoadWallet();
        load_ok = true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to open wallet: " << e.what() << "\n";
        load_ok = false;
    }

    if (!load_ok || !wallet) {
        std::cerr << "Could not load wallet from: " << datadir << "\n";
        ECC_Stop();
        return 1;
    }

    // Convert hex to bytes
    std::vector<unsigned char> mk = ParseHex(hex);
    CKeyingMaterial vMasterKey(mk.begin(), mk.end());

    // Try to find the ScriptPubKeyMan responsible for keys
    // Here we try the LegacyScriptPubKeyMan and DescriptorScriptPubKeyMan paths
    ScriptPubKeyMan* spk_man = nullptr;
    if (wallet->GetLegacyScriptPubKeyMan()) {
        spk_man = wallet->GetLegacyScriptPubKeyMan();
    } else if (wallet->GetDescriptorScriptPubKeyMan(/*internal=*/false)) {
        spk_man = wallet->GetDescriptorScriptPubKeyMan(false);
    }

    if (!spk_man) {
        std::cerr << "No ScriptPubKeyMan found in wallet (unexpected for legacy wallet)\n";
        memory_cleanse(vMasterKey.data(), vMasterKey.size());
        ECC_Stop();
        return 1;
    }

    // Check decryption key
    bool ok = spk_man->CheckDecryptionKey(vMasterKey, /*accept_no_keys=*/true);
    if (!ok) {
        std::cerr << "Master key did NOT decrypt wallet keys (wrong key)\n";
        memory_cleanse(vMasterKey.data(), vMasterKey.size());
        ECC_Stop();
        return 2;
    }

    std::cout << "Master key accepted — dumping private keys (WIF):\n";

    // Get all key IDs and attempt to get the private keys
    std::set<CKeyID> keys = spk_man->GetKeys();
    for (const CKeyID &kid : keys) {
        CKey key;
        if (!spk_man->GetKey(kid, key)) {
            std::cerr << "Could not get private key for " << kid.ToString() << "\n";
            continue;
        }
        CKeyIO keyio;
        // Convert to WIF
        std::string wif = EncodeSecret(key);
        std::cout << "KeyID: " << kid.ToString() << "  WIF: " << wif << "\n";
    }

    // cleanup
    memory_cleanse(vMasterKey.data(), vMasterKey.size());
    ECC_Stop();
    std::cout << "Done.\n";
    return 0;
}
