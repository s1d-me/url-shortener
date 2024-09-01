function extractBrowserInfo() {
    const referrer = document.referrer;
    const accept = navigator.userAgentData.platform;
    const screenResolution = `${window.screen.width}x${window.screen.height}`;
    const language = navigator.language;
    const plugins = navigator.plugins ? navigator.plugins.length : 'Not Available';

    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const colorDepth = window.screen.colorDepth;

    const os = navigator.userAgentData.platform;
    const userAgent = navigator.userAgent;
    document.getElementById('useragent').innerHTML = userAgent;
    document.getElementById("referrer").textContent = referrer;
    document.getElementById("accept").textContent = accept;
    document.getElementById("screen-resolution").textContent = screenResolution;
    document.getElementById("language").textContent = language;
    document.getElementById("plugins").textContent = plugins;
    document.getElementById("time-zone").textContent = timeZone;
    document.getElementById("color-depth").textContent = colorDepth;
    document.getElementById("os").textContent = os;

    fetch("https://api.ipify.org?format=json")
    .then(response => response.json())
    .then(data => {
      document.getElementById("ipv4").textContent = data.ip;
    })
    .catch(error => {
      console.error("Error fetching IP address:", error);
      document.getElementById("ipv4").textContent = "Error fetching IP";
    });

  fetch("https://api64.ipify.org?format=json")
    .then(response => response.json())
    .then(data => {
      document.getElementById("ipv6").textContent = data.ip;
    })
    .catch(error => {
      console.error("Error fetching IPv6 address:", error);
      document.getElementById("ipv6").textContent = "Error fetching IPv6";
    });
}
extractBrowserInfo();
