import streamlit as st
import requests
import tempfile
import subprocess
import zipfile
import base64
import re
import os
from openai import OpenAI

# Initialize OpenAI Client
llmClient = OpenAI(
    api_key="dummy",
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={
        "genaiplatform-farm-subscription-key": "e3b62450ed794963896276597b8bd87a"
    }
)


def fetch_cve_data(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id.strip().upper()}
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

        references = [ref["url"] for ref in cve_data.get("references", []) if "github.com" in ref["url"] or "git.openssl.org" in ref["url"]][:5]

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
            "patches": derived_patches[:5],
            "keywords": extract_keywords_from_description(description)
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def extract_keywords_from_description(description):
    words = re.findall(r'\b[a-zA-Z0-9_\.-]{4,}\b', description)
    common_stopwords = set(['this', 'that', 'with', 'from', 'were', 'which', 'where', 'also', 'have', 'been', 'will', 'affected', 'vulnerability', 'allows', 'could', 'before', 'after', 'such', 'into', 'some', 'when', 'while', 'issue', 'attack'])
    keywords = [w.lower() for w in words if w.lower() not in common_stopwords and not w.lower().startswith('cve')]
    return list(set(keywords))[:15]  # Limit to 15 unique keywords

def is_patch_relevant_to_cve(patch_path, cve_id, keywords=[]):
    try:
        with open(patch_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        content = ''.join(lines)
        modified_lines = [line[1:] for line in lines if line.startswith(('+', '-')) and not line.startswith(('+++', '---'))]

        cve_mentioned = cve_id.lower() in content.lower()
        keyword_hits = {k: any(k in line.lower() for line in modified_lines) for k in keywords}

        security_matches = [line.strip() for line in modified_lines if any(k in line.lower() for k in keywords)]

        return {
            "cve_mentioned": cve_mentioned,
            "keyword_hits": keyword_hits,
            "security_signs": list(set(security_matches))
        }
    except Exception as e:
        return {"error": f"Patch validation failed: {e}"}

def download_and_zip_patches(patch_urls, cve_id, keywords):
    all_relevance = []
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
        with zipfile.ZipFile(tmp_zip.name, "w") as zipf:
            for i, url in enumerate(patch_urls):
                try:
                    patch_name = f"patch_{i+1}.patch"
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".patch") as tmp_file:
                        curl_cmd = ["curl", "-L", url, "-o", tmp_file.name]
                        result = subprocess.run(curl_cmd, capture_output=True)
                        if result.returncode != 0:
                            raise Exception(result.stderr.decode())

                        relevance = is_patch_relevant_to_cve(tmp_file.name, cve_id, keywords)
                        all_relevance.append(relevance)

                        relevance_note = f"\n# CVE Mentioned: {relevance['cve_mentioned']}\n"
                        relevance_note += f"# Security signs: {len(relevance['security_signs'])} matches\n"

                        with open(tmp_file.name, 'a') as f:
                            f.write(relevance_note)

                        zipf.write(tmp_file.name, arcname=patch_name)
                except Exception as e:
                    print(f"[ERROR] Failed to download {url}: {e}")
                    continue
        return tmp_zip.name, all_relevance

def main():
    st.set_page_config(page_title="CVE Patch Relevance Checker", layout="wide")
    st.title("🔐 CVE Patch Relevance Checker")

    cve_id = st.text_input("Enter CVE ID (e.g. CVE-2023-0464):")

    if st.button("🔍 Fetch CVE Info"):
        with st.spinner("Fetching CVE data..."):
            data = fetch_cve_data(cve_id)

        if "error" in data:
            st.error(data["error"])
        else:
            st.session_state["cve_data"] = data
            st.success(f"CVE {data['id']} loaded")

    if "cve_data" in st.session_state:
        data = st.session_state["cve_data"]
        st.markdown(f"### Description{data['description']}")

        st.markdown("### 🔑 Keywords used for patch relevance search")
        st.code(", ".join(data.get("keywords", [])))

        st.markdown("### Recommendations")
        for rec in data["recommendations"]:
            st.markdown(f"- {rec}")

        if st.button("📦 Generate Patch ZIP with Relevance Info"):
            with st.spinner("Generating ZIP and checking relevance..."):
                zip_path, relevance_info = download_and_zip_patches(data["patches"], data["id"], data.get("keywords", []))
                with open(zip_path, "rb") as f:
                    st.session_state["patch_zip"] = f.read()
                st.session_state["relevance_info"] = relevance_info
                st.success("Patch ZIP is ready for download!")

    if "patch_zip" in st.session_state:
        st.download_button(
            label="⬇️ Click here to download patch ZIP",
            data=st.session_state["patch_zip"],
            file_name="patches.zip",
            mime="application/zip"
        )

        st.markdown("### 🔎 Patch Relevance Summary")
        for i, rel in enumerate(st.session_state.get("relevance_info", [])):
            cve_status = "✅ Relevant to CVE" if rel.get("cve_mentioned") else "⚠️ Possibly unrelated"
            signs = rel.get("security_signs", [])
            st.markdown(f"**Patch {i+1}:** {cve_status}, Security keywords found: {len(signs)}")
            if signs:
                st.code("\n".join(signs[:5]), language="diff")

if __name__ == "__main__":
    main()
