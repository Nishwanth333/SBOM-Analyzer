// Renders the "Average Risk Score by Application" bar chart on the dashboard.
// Expects `chartLabels` and `chartScores` arrays to be defined inline in dashboard.html.

document.addEventListener("DOMContentLoaded", () => {
  const ctx = document.getElementById("riskChart");
  if (!ctx || typeof chartLabels === "undefined") return;

  const barColors = chartScores.map((score) => {
    if (score >= 75) return "#ff6375"; // critical
    if (score >= 50) return "#ff9f5a"; // high
    if (score >= 25) return "#ffd078"; // medium
    return "#55d6b0";                  // low
  });
  const lowestScore = chartScores.length ? Math.min(...chartScores) : 0;
  const highestScore = chartScores.length ? Math.max(...chartScores) : 100;
  const axisMin = Math.max(0, Math.floor(lowestScore / 10) * 10 - 10);
  const axisMax = Math.min(100, Math.max(axisMin + 10, Math.ceil(highestScore / 10) * 10 + 5));

  new Chart(ctx, {
    type: "bar",
    data: {
      labels: chartLabels,
      datasets: [
        {
          label: "Avg Risk Score",
          data: chartScores,
          backgroundColor: barColors,
          borderRadius: 7,
          maxBarThickness: 42,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#112239",
          borderColor: "rgba(151, 180, 218, .2)",
          borderWidth: 1,
          titleColor: "#e8f0fb",
          bodyColor: "#cbd8e8",
          callbacks: {
            label: (item) => `Risk Score: ${item.raw}`,
          },
        },
      },
      scales: {
        y: {
          min: axisMin,
          max: axisMax,
          title: { display: true, text: "Risk Score", color: "#8da2bd" },
          grid: { color: "rgba(151, 180, 218, .10)" },
          ticks: { color: "#8da2bd", stepSize: 25 },
        },
        x: { grid: { display: false }, ticks: { color: "#aebfd3" } },
      },
    },
  });
});
