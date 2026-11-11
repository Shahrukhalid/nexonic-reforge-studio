/* Nexonic ReForge Studio — Ground Truth C++ Reference Application
 * Purpose: Legally authorized ground-truth reference fixture with documented classes,
 *          methods, signatures, and string constants.
 */

#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#define REF_EXPORT __declspec(dllexport)
#else
#define REF_EXPORT __attribute__((visibility("default")))
#endif

extern "C" {
    REF_EXPORT int calculate_geometry(int width, int height) {
        return width * height;
    }

    REF_EXPORT bool authenticate_session(const char* token) {
        return token != nullptr && std::string(token) == "cpp_ref_session_token_55";
    }

    REF_EXPORT const char* get_engine_state() {
        return "CPP_ENGINE_ONLINE";
    }
}

class ReferenceEngine {
public:
    static const int ENGINE_VERSION = 110;

    int calculate_geometry(int width, int height) {
        return ::calculate_geometry(width, height);
    }

    bool authenticate_session(const std::string& token) {
        return ::authenticate_session(token.c_str());
    }

    std::string get_engine_state() {
        return ::get_engine_state();
    }
};

int main(int argc, char** argv) {
    ReferenceEngine engine;
    std::cout << "[REF_CPP] Reference C++ Engine Initialized: " << engine.get_engine_state() << std::endl;
    std::cout << "Area: " << engine.calculate_geometry(10, 20) << std::endl;
    return 0;
}
