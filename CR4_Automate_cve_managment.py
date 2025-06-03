import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import json
import webbrowser
from openai import OpenAI

# Initialize your LLM client (adjust with your actual credentials/endpoint)
llmClient = OpenAI(
    api_key="dummy",  # Overwritten by your API manager or insert your key here
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={"genaiplatform-farm-subscription-key": "e3b62450ed794963896276597b8bd87a"}
)
def queryLLM(promptQuery, model_name="gpt-4o-mini"):
    try:
        completion = llmClient.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": promptQuery}],
            extra_query={"api-version": "2024-08-01-preview"},
            temperature=0.8
        )
        print("LLM Response:", completion)  # Debug print full response
        return completion.choices[0].message.content
    except Exception as e:
        print("LLM Query Error:", e)  # Print error
        return f"An error occurred during LLM query: {e}"


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
        cvss_score = None
        severity_level = None
        vector = None

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
            recommendations.append("Patch or upgrade the affected software immediately.")
            recommendations.append("Check vendor advisories for fixed versions.")
            recommendations.append("Monitor systems for signs of exploitation.")
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


class CVEApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Automated CVE Management")

        self.geometry("800x600")

        tk.Label(self, text="Enter CVE ID:", font=("Arial", 12)).pack(pady=5)
        self.cve_entry = tk.Entry(self, width=30, font=("Arial", 12))
        self.cve_entry.pack(pady=5)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        fetch_btn = tk.Button(btn_frame, text="Fetch CVE Info", command=self.fetch_cve)
        fetch_btn.grid(row=0, column=0, padx=5)

        llm_btn = tk.Button(btn_frame, text="Get LLM Patch Advice", command=self.get_llm_advice)
        llm_btn.grid(row=0, column=1, padx=5)

        self.output = scrolledtext.ScrolledText(self, font=("Consolas", 11), wrap=tk.WORD)
        self.output.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def fetch_cve(self):
        cve_id = self.cve_entry.get().strip()
        if not cve_id:
            messagebox.showwarning("Input Error", "Please enter a CVE ID.")
            return
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"Fetching data for {cve_id}...\n")
        data = fetch_cve_data(cve_id)

        if "error" in data:
            self.output.insert(tk.END, f"Error: {data['error']}\n")
            return

        self._display_result(data)

    def _display_result(self, data):
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"CVE ID: {data['id']}\n")
        self.output.insert(tk.END, f"Published: {data['published']}\n")
        self.output.insert(tk.END, f"Last Modified: {data['lastModified']}\n\n")
        self.output.insert(tk.END, f"Description:\n{data['description']}\n\n")
        self.output.insert(tk.END, f"CVSS Score: {data['cvss_score']}\n")
        self.output.insert(tk.END, f"Severity: {data['severity']}\n")
        self.output.insert(tk.END, f"Vector: {data['vector']}\n\n")
        self.output.insert(tk.END, "Recommendations:\n")
        for rec in data['recommendations']:
            self.output.insert(tk.END, f"  - {rec}\n")

        self.output.insert(tk.END, "\nReferences:\n")
        for i, ref in enumerate(data['references']):
            start_index = self.output.index(tk.END)
            self.output.insert(tk.END, f"{ref}\n")
            end_index = self.output.index(tk.END)

            tag_name = f"link{i}"
            self.output.tag_add(tag_name, start_index, end_index)
            self.output.tag_config(tag_name, foreground="blue", underline=1)
            self.output.tag_bind(tag_name, "<Button-1>", lambda e, url=ref: webbrowser.open_new(url))

    def get_llm_advice(self):
        cve_id = self.cve_entry.get().strip()
        if not cve_id:
            messagebox.showwarning("Input Error", "Please enter a CVE ID to get advice.")
            return
        self.output.insert(tk.END, "\n\nFetching patching advice from LLM...\n")
        prompt = f"Provide detailed patching and mitigation advice for the vulnerability {cve_id}."
        advice = queryLLM(prompt)
        self.output.insert(tk.END, f"\n=== LLM Advice ===\n{advice}\n")


if __name__ == "__main__":
    
    #print(queryLLM("Provide patching advice for CVE-2023-0464"))
    app = CVEApp()
    app.mainloop()
