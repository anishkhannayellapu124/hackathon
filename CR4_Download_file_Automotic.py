import streamlit as st
import requests
from openai import OpenAI
import tempfile
import os
import base64
import zipfile

# LLM initialization
llmClient = OpenAI(
    api_key="dummy",
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={
        "genaiplatform-farm-subscription-key": "e3b62450ed794963896276597b8bd87a"
    }
)

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

        return {
            "id": cve_data.get("id"),
            "published": cve_data.get("published"),
            "lastModified": cve_data.get("lastModified"),
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity_level,
            "vector": vector,
            "recommendations": recommendations,
            "references": [ref["url"] for ref in cve_data.get("references", [])],
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def display_pdf(file_path):
    with open(file_path, "rb") as f:
        base64_pdf = base64.b64encode(f.read()).decode("utf-8")
    pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="700" height="1000" type="application/pdf"></iframe>'
    st.markdown(pdf_display, unsafe_allow_html=True)

def main():
    st.title("🔐 CVE Management Assistant")

    cve_id = st.text_input("Enter CVE ID (e.g. CVE-2023-0464):")

    fetch_clicked = st.button("🔍 Fetch CVE Info")
    llm_clicked = st.button("🤖 Get LLM Patch Advice")

    if fetch_clicked:
        if not cve_id:
            st.warning("Please enter a CVE ID.")
        else:
            with st.spinner(f"Fetching data for {cve_id}..."):
                data = fetch_cve_data(cve_id)

            if "error" in data:
                st.error(data["error"])
            else:
                st.subheader(f"CVE ID: {data['id']}")
                st.write(f"📅 Published: {data['published']}")
                st.write(f"🛠️ Last Modified: {data['lastModified']}")
                st.write(f"📝 Description:\n\n{data['description']}")
                st.write(f"📊 CVSS Score: `{data['cvss_score']}` | Severity: `{data['severity']}`")
                st.write(f"🧭 Vector: `{data['vector']}`")

                st.markdown("### ✅ Recommendations")
                for rec in data["recommendations"]:
                    st.markdown(f"- {rec}")

                st.markdown("### 🔗 References (First 5)")
                first_5_refs = data["references"][:5]
                for url in first_5_refs:
                    st.markdown(f"[{url}]({url})")

                if first_5_refs:
                    try:
                        st.markdown("### 📥 Download & Preview First Reference")
                        first_url = first_5_refs[0]
                        ref_response = requests.get(first_url, timeout=10)
                        ref_response.raise_for_status()

                        suffix = ".pdf" if ".pdf" in first_url.lower() else ".html"
                        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
                        tmp_file.write(ref_response.content)
                        tmp_file.close()

                        with open(tmp_file.name, "rb") as f:
                            st.download_button("Download First Reference", f, file_name=os.path.basename(tmp_file.name))

                        if suffix == ".pdf":
                            display_pdf(tmp_file.name)
                        elif suffix == ".html":
                            with open(tmp_file.name, "r", encoding="utf-8", errors="ignore") as html_file:
                                html_content = html_file.read()
                                st.components.v1.html(html_content, height=600, scrolling=True)

                    except Exception as e:
                        st.error(f"Failed to preview: {e}")

                # ZIP download of all references
                if data["references"]:
                    with st.spinner("Preparing ZIP of all references..."):
                        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
                        with zipfile.ZipFile(zip_path, "w") as zipf:
                            for i, url in enumerate(data["references"]):
                                try:
                                    resp = requests.get(url, timeout=10)
                                    resp.raise_for_status()
                                    ext = ".pdf" if ".pdf" in url.lower() else ".html"
                                    fname = f"ref_{i+1}{ext}"
                                    temp_path = os.path.join(tempfile.gettempdir(), fname)
                                    with open(temp_path, "wb") as f:
                                        f.write(resp.content)
                                    zipf.write(temp_path, arcname=fname)
                                except Exception:
                                    continue

                        with open(zip_path, "rb") as f:
                            st.download_button(
                                label="📦 Download All References as ZIP",
                                data=f,
                                file_name="cve_references.zip",
                                mime="application/zip"
                            )

    if llm_clicked:
        if not cve_id:
            st.warning("Please enter a CVE ID.")
        else:
            with st.spinner("Querying LLM for patching advice..."):
                advice = queryLLM(f"Provide detailed patching and mitigation advice for the vulnerability {cve_id}.")
            st.subheader("🤖 LLM Advice")
            st.write(advice)

# Run the app
if __name__ == "__main__":
    main()
