#include <string>

#if !defined(DISABLE_SELINUX)
#include <selinux/android.h>
#include <selinux/avc.h>
#endif

namespace android {

class AccessControl {
public:
    AccessControl();
    bool canAdd(const std::string& fqName, pid_t pid);
    bool canGet(const std::string& fqName, pid_t pid);
    bool canList(pid_t pid);
private:
    bool checkPermission(pid_t sourcePid, const char *perm, const char *interface);
    bool checkPermission(pid_t sourcePid, const char *targetContext, const char *perm, const char *interface);

#if !defined(DISABLE_SELINUX)
    static int auditCallback(void *data, security_class_t cls, char *buf, size_t len);

    char*                  mSeContext;
    struct selabel_handle* mSeHandle;
    union selinux_callback mSeCallbacks;
#endif
};

} // namespace android
