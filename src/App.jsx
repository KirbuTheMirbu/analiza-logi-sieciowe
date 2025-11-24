import React, { useState, useEffect, useRef } from "react";
import Chart from "chart.js/auto";

export default function LogProcessor() {
  const [rawText, setRawText] = useState("");
  const [records, setRecords] = useState([]);
  const [anomalies, setAnomalies] = useState({
    bruteForce: [],
    portScans: [],
    suspiciousIPs: []
  });
  const [summary, setSummary] = useState({ total: 0 });

  const bruteChartRef = useRef(null);
  const portChartRef = useRef(null);
  const blackChartRef = useRef(null);
  const timelineChartRef = useRef(null);

  const bruteInstance = useRef(null);
  const portInstance = useRef(null);
  const blackInstance = useRef(null);
  const timelineInstance = useRef(null);

  //przykładowa  czarna lista
  const localBlacklist = ["203.0.113.45", "198.51.100.23"];

  //funkcja pomocnicza do parsowania daty ze stringa
  function parseTimestamp(s) {
    const d = new Date(s);
    if (!isNaN(d)) return d;
    const m = s.match(/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/);
    if (m) return new Date(`${m[0]} 2025`);
    return null;
  }

  //próba sparsowania jednej linii logu w CLF lub key=value
  function parseLogLine(line) {
    line = line.trim();
    if (!line) return null;

    //1. JSON
    if (line.startsWith("{") && line.endsWith("}")) {
      try {
        return normalizeRecord(JSON.parse(line));
      } catch {}
    }

    //2. CSV: ip,time,request,status,port
    const csvParts = line.split(",");
    if (csvParts.length >= 3 && csvParts[0].match(/^\d+\.\d+\.\d+\.\d+$/)) {
      const [src, time, request, status, port] = csvParts.map((p) => p.trim());
      return normalizeRecord({ srcIP: src, time, request, status, port });
    }

    //3. CLF: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    const clfMatch = line.match(
      /^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d{3}) (\d+|-)$/);
    if (clfMatch) {
      return normalizeRecord({
        srcIP: clfMatch[1],
        time: clfMatch[2],
        request: clfMatch[3],
        status: clfMatch[4]
      });
    }

    //4. Key=Value style: src=1.2.3.4 dst=5.6.7.8 port=22 status=Failed
    const kvPairs = line.match(/(\w+=[^\s]+)/g);
    if (kvPairs) {
      const kv = {};
      kvPairs.forEach((p) => {
        const [k, v] = p.split("=");
        kv[k] = v;
      });
      return normalizeRecord(kv);
    }

    //5. Syslog-like: "Nov 06 09:12:04 sshd[2145]: Failed password for invalid user admin from 198.51.100.23 port 45678 ssh2"
    const syslogMatch = line.match(
      /from (\d{1,3}(?:\.\d{1,3}){3}) port (\d+)/);
    if (syslogMatch) {
      const [_, srcIP, port] = syslogMatch;
      const timeMatch = line.match(
        /^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/);
      const time = timeMatch ? timeMatch[0] : undefined;
      const failed =
        line.toLowerCase().includes("failed") ||
        line.toLowerCase().includes("brute");
      return normalizeRecord({
        srcIP,
        port,
        time,
        status: failed ? "Failed" : "OK",
        request: line
      });
    }

    //6. Kernel or IDS logs
    const kernelMatch = line.match(
      /SRC=(\d{1,3}(?:\.\d{1,3}){3}).*DPT=(\d+)/);
    if (kernelMatch) {
      const [_, srcIP, port] = kernelMatch;
      const timeMatch = line.match(
        /^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/);
      const time = timeMatch ? timeMatch[0] : undefined;
      return normalizeRecord({ srcIP, port, time, request: line });
    }

    // 7. Syslog timestamp bez portów, np. "Nov 06 09:16:30 firewall:"
    const sysTs = line.match(/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/);
    if (sysTs) {
      return normalizeRecord({
        time: sysTs[0],
        request: line,
        raw: line
      });
    }

    //8. Fallback: próba znalezienia IP i timestampa
    const ip = line.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    return normalizeRecord({
      srcIP: ip ? ip[1] : undefined,
      raw: line
    });
  }

  //normalizacja pola rekordu do przewidywalnego formatu
  function normalizeRecord(obj) {
    const r = {
      srcIP:
        obj.srcIP || obj.ip || obj.client || obj.src || obj.source,
      destIP:
        obj.destIP ||
        obj.dst ||
        obj.destination ||
        obj.server ||
        obj.dest,
      time: obj.time || obj.timestamp || obj.ts || obj.date,
      request: obj.request || obj.method || obj.msg,
      status: obj.status || obj.code || obj.result,
      port: obj.port ? Number(obj.port) : undefined,
      raw: obj.raw || JSON.stringify(obj)
    };

    //parsowanie timestampa
    r.parsedTime = r.time ? parseTimestamp(r.time) : null;
    return r;
  }

  //funkcja główna do parsowania całego tekstu pliku
  function parseText(text) {
    const lines = text.split(/\r?\n/);
    const recs = lines.map(parseLogLine).filter(Boolean);
    setRecords(recs);
    setSummary({ total: recs.length });
    detectAnomalies(recs);
  }

  //wykrywanie prostych anomalii
  function detectAnomalies(recs) {
    const now = Date.now();

    //Brute force: duża liczba nieudanych prób logowania z jednego adresu IP
    //Heurystyka: jeśli dla IP > N prób z status 'Failed' lub status kod 401/403 w oknie T sekund
    const BF_THRESHOLD = 5;
    const BF_WINDOW_MS = 10 * 60 * 1000; //10 minut

    const byIP = {};
    recs.forEach((r) => {
      const ip = r.srcIP || "unknown";
      if (!byIP[ip]) byIP[ip] = [];
      byIP[ip].push(r);
    });

    const brute = [];
    Object.entries(byIP).forEach(([ip, arr]) => {
      //sortuj po czasie
      const times = arr
        .map((x) => ({
          t: x.parsedTime ? x.parsedTime.getTime() : now,
          status: x.status
        }))
        .sort((a, b) => (a.t || 0) - (b.t || 0));

      //liczenie porażek
      for (let i = 0; i < times.length; i++) {
        const start = times[i].t;
        let count = 0;

        for (let j = i; j < times.length; j++) {
          if (times[j].t - start <= BF_WINDOW_MS) {
            const st = (times[j].status || "").toLowerCase();
            if (st.includes("fail")) count++;
          }
        }

        if (count >= BF_THRESHOLD) {
          brute.push({ ip, attempts: count });
          break;
        }
      }
    });

    //Port scanning: wiele prób na różnych portach w krótkim czasie
    //Heurystyka: dla jednego srcIP wykryj liczbę unikalnych portów >= P w oknie W
    const PS_THRESHOLD = 1;
    const PS_WINDOW_MS = 5 * 60 * 1000; //5 minut

    const scans = [];
    Object.entries(byIP).forEach(([ip, arr]) => {
      const withPorts = arr.filter((r) => r.port);
      if (!withPorts.length) return;

      const times = withPorts
        .map((x) => ({
          t: x.parsedTime ? x.parsedTime.getTime() : now,
          port: x.port
        }))
        .sort((a, b) => a.t - b.t);

      for (let i = 0; i < times.length; i++) {
        const start = times[i].t;
        const ports = new Set();

        for (let j = i; j < times.length; j++) {
          if (times[j].t - start <= PS_WINDOW_MS) {
            ports.add(times[j].port);
          }
        }

        if (ports.size >= PS_THRESHOLD) {
          scans.push({ ip, uniquePorts: ports.size });
          break;
        }
      }
    });

    //blacklista
    const suspicious = {};
    recs.forEach((r) => {
      if (localBlacklist.includes(r.srcIP)) {
        suspicious[r.srcIP] = (suspicious[r.srcIP] || 0) + 1;
      }
    });

    setAnomalies({
      bruteForce: brute,
      portScans: scans,
      suspiciousIPs: Object.entries(suspicious).map(([ip, count]) => ({ ip, count }))
    });
  }

  //tworzenie wykresów
  useEffect(() => {
    //brute force
    if (bruteInstance.current) bruteInstance.current.destroy();
    bruteInstance.current = new Chart(bruteChartRef.current, {
      type: "bar",
      data: {
        labels: anomalies.bruteForce.map((x) => x.ip),
        datasets: [
          {
            label: "Brute-force attempts",
            data: anomalies.bruteForce.map((x) => x.attempts)
          }
        ]
      }
    });

    //port scan
    if (portInstance.current) portInstance.current.destroy();
    portInstance.current = new Chart(portChartRef.current, {
      type: "bar",
      data: {
        labels: anomalies.portScans.map((x) => x.ip),
        datasets: [
          {
            label: "Unique ports probed",
            data: anomalies.portScans.map((x) => x.uniquePorts)
          }
        ]
      }
    });

    //blacklista
    if (blackInstance.current) blackInstance.current.destroy();
    blackInstance.current = new Chart(blackChartRef.current, {
      type: "bar",
      data: {
        labels: anomalies.suspiciousIPs.map((x) => x.ip),
        datasets: [
          {
            label: "Blacklist occurrences",
            data: anomalies.suspiciousIPs.map((x) => x.count)
          }
        ]
      }
    });

    //liniowy
    if (timelineInstance.current) timelineInstance.current.destroy();

    const timeline = {};

    records.forEach((r) => {
      if (!r.parsedTime) return;

      // zaokrąglenie do pełnej minuty
      const t = new Date(r.parsedTime);
      t.setSeconds(0);
      t.setMilliseconds(0);

      // lokalne HH:MM (bez UTC!)
      const key =
        String(t.getHours()).padStart(2, "0") +
        ":" +
        String(t.getMinutes()).padStart(2, "0");

      timeline[key] = (timeline[key] || 0) + 1;
});

// sortowanie chronologiczne (ważne!)
const sortedKeys = Object.keys(timeline).sort(
  (a, b) => {
    const [ah, am] = a.split(":").map(Number);
    const [bh, bm] = b.split(":").map(Number);
    return ah * 60 + am - (bh * 60 + bm);
  }
);

timelineInstance.current = new Chart(timelineChartRef.current, {
  type: "line",
  data: {
    labels: sortedKeys,
    datasets: [
      {
        label: "Aktywność logów w czasie",
        data: sortedKeys.map((k) => timeline[k]),
        fill: false,
      },
    ],
  },
});
  }, [anomalies, records]);

  //handler wczytania pliku przez input[type=file]
  function handleFileChange(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => parseText(ev.target.result);
    reader.readAsText(file);
  }

  //eksport wyników jako CSV
  function exportCSV() {
    if (!records.length) return;
    const headers = ["srcIP", "destIP", "time", "request", "status", "port"];
    const lines = [
      headers.join(","),
      ...records.map((r) =>
        headers.map((h) => JSON.stringify(r[h] ?? "")).join(",")
      )
    ];
    const blob = new Blob([lines.join("\n")], {
      type: "text/csv;charset=utf-8;"
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "parsed_logs.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ padding: 12, fontFamily: "system-ui, Arial" }}>
      <h2>Wybierz plik .log / .csv / .json / .txt</h2>
      <input type="file"
             accept=".log,.txt,.csv,.json"
             onChange={handleFileChange} />

      <div style={{ marginTop: 12 }}>
        <strong>Podsumowanie:</strong>
        <div>Liczba rekordów: {summary.total}</div>
        <div>Brute-force IP: {anomalies.bruteForce.length}</div>
        <div>Port-scan IP: {anomalies.portScans.length}</div>
        <div>Blacklisted IP: {anomalies.suspiciousIPs.length}</div>
      </div>

      <button
        onClick={exportCSV}
        disabled={!records.length}
        style={{ marginTop: 12 }}
      >
        Eksportuj CSV
      </button>

      <h3 style={{ marginTop: 20 }}>Wykresy anomalii</h3>

      <div style={{ width: "600px", marginTop: 20 }}>
        <h4>Ataki brute-force</h4>
        <canvas ref={bruteChartRef}></canvas>
      </div>

      <div style={{ width: "600px", marginTop: 20 }}>
        <h4>Ataki port-scan</h4>
        <canvas ref={portChartRef}></canvas>
      </div>

      <div style={{ width: "600px", marginTop: 20 }}>
        <h4>Zablokowane IP</h4>
        <canvas ref={blackChartRef}></canvas>
      </div>

      <div style={{ width: "800px", marginTop: 40 }}>
        <h3>Aktywność logów</h3>
        <canvas ref={timelineChartRef}></canvas>
      </div>
    </div>
  );
}