function dashboard() {
  return {
    target: "",
    loading: false,
    error: "",
    result: null,
    apiBase: (() => {
      const override = window.VULNVISION_API_BASE;
      if (override) {
        return override.replace(/\/$/, "");
      }
      const origin = window.location.origin;
      if (origin && origin.startsWith("http")) {
        return origin.replace(/\/$/, "");
      }
      return "http://localhost:8000";
    })(),

    badgeClass(level) {
      if (!level) return "badge-muted";
      const key = level.toString().toLowerCase();
      switch (key) {
        case "high":
          return "badge-high";
        case "medium":
          return "badge-medium";
        case "low":
          return "badge-low";
        default:
          return "badge-muted";
      }
    },

    headerBadge(status) {
      const key = status ? status.toLowerCase() : "";
      switch (key) {
        case "secure":
          return "badge-low";
        case "needs_review":
          return "badge-medium";
        case "missing":
          return "badge-high";
        default:
          return "badge-muted";
      }
    },

    formatHeaderStatus(status) {
      if (!status) return "Unknown";
      return status.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
    },

    capitalize(value) {
      if (!value) return "";
      return value.charAt(0).toUpperCase() + value.slice(1);
    },

    formatKey(summary) {
      if (!summary) return "Unknown";
      const size = summary.key_size ? `${summary.key_size} bits` : "Unknown size";
      return `${summary.key_type || "Unknown"} (${size})`;
    },

    formatDate(value) {
      if (!value) return "Unknown";
      try {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return value;
        return date.toLocaleString();
      } catch (_err) {
        return value;
      }
    },

    async runScan() {
      if (!this.target) {
        this.error = "Enter a target URL.";
        return;
      }
      this.loading = true;
      this.error = "";
      try {
        const response = await fetch(`${this.apiBase}/scan`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ target: this.target }),
        });
        if (!response.ok) {
          const data = await response.json().catch(() => ({ detail: response.statusText }));
          throw new Error(data.detail || "Scan failed.");
        }
        this.result = await response.json();
      } catch (err) {
        console.error(err);
        this.error = err.message || "Failed to run scan.";
      } finally {
        this.loading = false;
      }
    },

    async downloadReport() {
      if (!this.target) {
        this.error = "Enter a target URL before exporting.";
        return;
      }
      this.loading = true;
      this.error = "";
      try {
        const response = await fetch(`${this.apiBase}/report`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ target: this.target }),
        });
        if (!response.ok) {
          const data = await response.json().catch(() => ({ detail: response.statusText }));
          throw new Error(data.detail || "Failed to generate report.");
        }
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        const safeHost = this.target.replace(/https?:\/\//, "").replace(/[^a-z0-9.-]+/gi, "-");
        link.download = `vulnvision-${safeHost || "report"}.html`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
      } catch (err) {
        console.error(err);
        this.error = err.message || "Failed to export report.";
      } finally {
        this.loading = false;
      }
    },
  };
}
