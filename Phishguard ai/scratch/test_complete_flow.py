import requests

base = "http://127.0.0.1:5000"

def test_full_system_flow():
    print("==================================================")
    print("STARTING END-TO-END FLOW VERIFICATION")
    print("==================================================")

    # -------------------------------------------------------------------------
    # 1. USER WORKFLOW
    # -------------------------------------------------------------------------
    user_sess = requests.Session()
    print("\n1. USER LOGIN:")
    res = user_sess.post(f"{base}/api/auth/login", json={"identifier": "demo_user", "password": "user123"})
    assert res.status_code == 200 and res.json().get("role") == "user"
    print("   [PASS] Logged in as demo_user (role: user)")

    print("\n2. USER RUNS A SCAN:")
    scan_res = user_sess.post(f"{base}/api/scan/url", json={"url": "https://paypal-security-update-account.xyz/login"})
    scan_data = scan_res.json()
    assert scan_res.status_code == 200 and scan_data.get("success") is True
    scan_id = scan_data["scan_id"]
    print(f"   [PASS] Scan completed. Scan #{scan_id}, Verdict: {scan_data['verdict']}, Score: {scan_data['risk_score']}")

    print("\n3. USER VIEWS SCAN DETAILS:")
    view_res = user_sess.get(f"{base}/api/scan/{scan_id}")
    assert view_res.status_code == 200 and view_res.json().get("success") is True
    print(f"   [PASS] Retrieved scan #{scan_id} details")

    print("\n4. USER REPORTS THE SCAN TO SECURITY TEAM:")
    rep_res = user_sess.post(f"{base}/api/reports", json={"scan_id": scan_id, "reason": "Fake login link asking for credentials"})
    rep_data = rep_res.json()
    assert rep_res.status_code in (200, 201) and rep_data.get("success") is True
    report_id = rep_data["report_id"]
    print(f"   [PASS] Report submitted. Report #{report_id}")

    # Verify regular user is BLOCKED from analyst/admin views:
    analyst_block = user_sess.get(f"{base}/analyst", allow_redirects=False)
    assert analyst_block.status_code == 302
    print("   [PASS] Normal user correctly blocked from /analyst")

    admin_block = user_sess.get(f"{base}/admin", allow_redirects=False)
    assert admin_block.status_code == 302
    print("   [PASS] Normal user correctly blocked from /admin")


    # -------------------------------------------------------------------------
    # 2. SECURITY ANALYST WORKFLOW
    # -------------------------------------------------------------------------
    analyst_sess = requests.Session()
    print("\n5. SECURITY ANALYST LOGIN:")
    res = analyst_sess.post(f"{base}/api/auth/login", json={"identifier": "security_analyst", "password": "analyst123"})
    assert res.status_code == 200 and res.json().get("role") == "analyst"
    print("   [PASS] Logged in as security_analyst (role: analyst)")

    print("\n6. ANALYST CHECKS QUEUE & FINDS REPORT:")
    queue_res = analyst_sess.get(f"{base}/api/reports")
    reports = queue_res.json().get("reports", [])
    found = any(r["id"] == report_id for r in reports)
    assert found, f"Report #{report_id} not found in analyst queue"
    print(f"   [PASS] Report #{report_id} visible in analyst triage queue")

    print("\n7. ANALYST RESOLVES REPORT:")
    resolve_res = analyst_sess.post(f"{base}/api/reports/{report_id}/status", json={"status": "resolved"})
    assert resolve_res.status_code == 200 and resolve_res.json().get("success") is True
    print(f"   [PASS] Report #{report_id} marked as 'resolved'")

    # Verify analyst blocked from admin console
    admin_block_analyst = analyst_sess.get(f"{base}/admin", allow_redirects=False)
    assert admin_block_analyst.status_code == 302
    print("   [PASS] Security analyst correctly blocked from /admin")


    # -------------------------------------------------------------------------
    # 3. ADMINISTRATOR WORKFLOW
    # -------------------------------------------------------------------------
    admin_sess = requests.Session()
    print("\n8. ADMINISTRATOR LOGIN:")
    res = admin_sess.post(f"{base}/api/auth/login", json={"identifier": "admin_manager", "password": "admin123"})
    assert res.status_code == 200 and res.json().get("role") == "admin"
    print("   [PASS] Logged in as admin_manager (role: admin)")

    print("\n9. ADMIN CHECKS COMPANY TELEMETRY & ADDS TO BLOCKLIST:")
    block_res = admin_sess.post(f"{base}/api/admin/blocklist", json={"domain": "paypal-security-update-account.xyz", "reason": "Confirmed Harvester"})
    assert block_res.status_code == 200 and block_res.json().get("success") is True
    print("   [PASS] Malicious domain added to company blocklist")

    print("\n10. ADMIN CREATES AND REMOVES A USER ACCOUNT:")
    create_u = admin_sess.post(f"{base}/api/admin/users", json={
        "username": "flow_test_emp",
        "email": "emp@company.com",
        "password": "temppassword123",
        "role": "user"
    })
    assert create_u.status_code in (200, 201)
    new_uid = create_u.json()["user_id"]
    print(f"   [PASS] Created employee account #{new_uid}")

    del_u = admin_sess.delete(f"{base}/api/admin/users/{new_uid}")
    assert del_u.status_code == 200 and del_u.json().get("success") is True
    print(f"   [PASS] Removed employee account #{new_uid}")

    print("\n==================================================")
    print("ALL LOGIC FLOWS & ROLE SEPARATIONS VERIFIED!")
    print("==================================================")

if __name__ == "__main__":
    test_full_system_flow()
