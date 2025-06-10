import streamlit as st
import requests
import base64
import tempfile
import zipfile
import os
import re
import subprocess

# Updated LLM function using real client
from openai import OpenAI
# LLM initialization
llmClient = OpenAI(
    api_key="dummy",
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={
        "genaiplatform-farm-subscription-key": "e3b62450ed794963896276597b8bd87a"
    }
)

def fetch_cve_data(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"User-Agent": "CVE-Fetcher/1.0"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": f"No CVE data found for {cve_id}"}

        cve_data = vulnerabilities[0].get("cve", {})
        description = next(
            (desc["value"] for desc in cve_data.get("descriptions", []) if desc["lang"] == "en"),
            "No English description available."
        )

        metrics = cve_data.get("metrics", {})
        cvss_score = severity_level = vector = None

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]
        else:
            cvss = None

        if cvss:
            cvss_score = cvss.get("cvssData", {}).get("baseScore")
            severity_level = cvss.get("cvssData", {}).get("baseSeverity", "Unknown")
            vector = cvss.get("cvssData", {}).get("vectorString")

        # Recommendations
        recommendations = []
        if severity_level in ("HIGH", "CRITICAL"):
            recommendations.extend([
                "Patch or upgrade the affected software immediately.",
                "Check vendor advisories for fixed versions.",
                "Monitor systems for signs of exploitation."
            ])
        elif severity_level == "MEDIUM":
            recommendations.append("Schedule patching in your next maintenance window.")
        elif severity_level == "LOW":
            recommendations.append("Monitor but prioritize based on exposure.")
        else:
            recommendations.append("Review vulnerability manually due to unknown severity.")

        if vector and "NETWORK" in vector.upper():
            recommendations.append("Expose affected services behind a firewall or VPN.")
            recommendations.append("Limit network access to trusted sources.")

        # Top 5 references
        references = [ref["url"] for ref in cve_data.get("references", []) if "github.com" in ref["url"] or "git.openssl.org" in ref["url"]][:5]

        # Derive patch URLs
        patch_urls = []
        for url in references:
            if re.match(r'https://github\.com/[^/]+/[^/]+/commit/[a-f0-9]+$', url):
                patch_urls.append(url + '.patch')
            elif 'git.openssl.org' in url and 'commitdiff' in url:
                match = re.search(r'h=([a-f0-9]+)', url)
                if match:
                    commit_hash = match.group(1)
                    github_patch = f'https://github.com/openssl/openssl/commit/{commit_hash}.patch'
                    patch_urls.append(github_patch)
                else:
                    patch_urls.append(url)
            else:
                patch_urls.append(url)

        derived_patches = list(set(patch_urls))

        return {
            "id": cve_data.get("id"),
            "published": cve_data.get("published"),
            "lastModified": cve_data.get("lastModified"),
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity_level,
            "vector": vector,
            "recommendations": recommendations,
            "references": references,
            "patches": derived_patches[:5]
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
    

   
def get_actual_url_and_ext(url):
    # Case 1: GitHub direct commit
    match = re.match(r'(https://github\.com/[^/]+/[^/]+/commit/[a-f0-9]+)', url)
    if match:
        patch_url = match.group(1) + ".patch"
        print(f"[INFO] Converted GitHub Patch URL: {patch_url}")
        return patch_url, '.patch'

    # Case 2: git.openssl.org format
    if "git.openssl.org" in url and "commitdiff" in url:
        project_match = re.search(r'p=([a-zA-Z0-9_-]+)\.git', url)
        commit_match = re.search(r'h=([a-f0-9]{8,40})', url)
        if project_match and commit_match:
            project = project_match.group(1)
            commit_hash = commit_match.group(1)
            # Map OpenSSL git to GitHub equivalent
            github_url = f"https://github.com/openssl/{project}/commit/{commit_hash}.patch"
            print(f"[INFO] Mapped OpenSSL Git to GitHub Patch URL: {github_url}")
            return github_url, '.patch'

    # Fallbacks
    if url.endswith('.pdf'):
        return url, '.pdf'
    elif url.endswith('.patch') or url.endswith('.diff'):
        return url, '.patch'
    elif url.endswith('.html') or url.endswith('.htm'):
        return url, '.html'
    else:
        return url, '.txt'



    
def display_pdf(file_path):
    with open(file_path, "rb") as f:
        base64_pdf = base64.b64encode(f.read()).decode("utf-8")
    pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="700" height="1000" type="application/pdf"></iframe>'
    st.markdown(pdf_display, unsafe_allow_html=True)

def display_reference_preview(references):
    for url in references:
        if url.endswith(".pdf") or url.endswith(".html") or url.endswith(".htm"):
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                st.markdown(f"#### Preview: [{url}]({url})")
                st.markdown(f"<iframe src=\"{url}\" width=\"100%\" height=\"500\"></iframe>", unsafe_allow_html=True)
                break
            except:
                continue
        elif 'github.com' in url and '/commit/' in url:
            st.markdown(f"#### Git Commit Reference: [{url}]({url})")
            break

def queryLLM(promptQuery, model_name="gpt-4o-mini"):
    try:
        completion = llmClient.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": promptQuery}],
            extra_query={"api-version": "2024-08-01-preview"},
            temperature=0.8
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"LLM Query Error: {e}"

def download_and_zip_patches(patch_urls):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
        with zipfile.ZipFile(tmp_zip.name, "w") as zipf:
            for i, url in enumerate(patch_urls):
                try:
                    actual_url, ext = get_actual_url_and_ext(url)

                    # Log the URLs being used
                    print(f"[INFO] Original URL: {url}")
                    print(f"[INFO] Converted Patch URL: {actual_url}")

                    if actual_url.endswith(".patch") and "github.com" in actual_url:
                        print(f"[INFO] Using curl to download: {actual_url}")
                        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_file:
                            curl_cmd = [
                                "curl",
                                "-L", actual_url,
                                "-H", "Accept: application/vnd.github.v3.patch",
                                "-o", tmp_file.name
                            ]
                            result = subprocess.run(curl_cmd, capture_output=True)
                            if result.returncode != 0:
                                raise Exception(result.stderr.decode())
                            zipf.write(tmp_file.name, arcname=f"patch_{i+1}{ext}")
                    else:
                        print(f"[INFO] Using requests to download: {actual_url}")
                        resp = requests.get(actual_url, timeout=10)
                        resp.raise_for_status()
                        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_file:
                            tmp_file.write(resp.content)
                            zipf.write(tmp_file.name, arcname=f"patch_{i+1}{ext}")

                except Exception as e:
                    print(f"[ERROR] Failed to download {url}: {e}")
                    continue
        return tmp_zip.name



def main():
    st.title("🔐 CVE Patch & Advisory Viewer")

    cve_id = st.text_input("Enter CVE ID (e.g. CVE-2023-0464):")
    fetch_clicked = st.button("Fetch CVE Info")
    llm_clicked = st.button("Get LLM Recommendations")

    if fetch_clicked and cve_id:
        with st.spinner("Fetching CVE details..."):
            data = fetch_cve_data(cve_id)

        if "error" in data:
            st.error(data["error"])
        else:
            st.subheader(f"CVE: {data['id']}")
            st.write(f"Published: {data['published']}")
            st.write(f"Last Modified: {data['lastModified']}")
            st.markdown(f"**Description:** {data['description']}")
            st.write(f"CVSS Score: {data['cvss_score']} | Severity: {data['severity']}")
            st.write(f"Vector: {data['vector']}")

            st.markdown("### ✅ Recommendations")
            for rec in data["recommendations"]:
                st.markdown(f"- {rec}")

            st.markdown("### 🔗 References (Top 5)")
            for ref in data["references"]:
                st.markdown(f"- [{ref}]({ref})")

            st.markdown("### 🧩 Patch Preview (if available)")
            display_reference_preview(data["references"])

            st.markdown("### 📦 Download Patches as ZIP")
            zip_path = download_and_zip_patches(data["patches"])
            with open(zip_path, "rb") as f:
                st.download_button("Download Patch ZIP", f, file_name="patches.zip")

    if llm_clicked and cve_id:
        with st.spinner("Querying LLM for patching advice..."):
            advice = queryLLM(f"Provide detailed patching and mitigation advice for the vulnerability {cve_id}.")
        st.subheader("🤖 LLM Advice")
        st.write(advice)

if __name__ == "__main__":
    main()
