import { useEffect, useState } from "react";
import axios from "axios";

const ITEMS_PER_PAGE = 6;

function GroupedAttacks() {
  const [groups, setGroups] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:8000/grouped-attacks")
      .then((res) => {
        const sortedGroups = (res.data.groups || []).sort(
          (a, b) => (b.attack_count || 0) - (a.attack_count || 0)
        );
        setGroups(sortedGroups);
      })
      .catch((err) => console.error(err));
  }, []);

  const totalPages = Math.max(1, Math.ceil(groups.length / ITEMS_PER_PAGE));
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginatedGroups = groups.slice(startIndex, startIndex + ITEMS_PER_PAGE);

  const goToNextPage = () => {
    setCurrentPage((prev) => Math.min(prev + 1, totalPages));
  };

  const goToPrevPage = () => {
    setCurrentPage((prev) => Math.max(prev - 1, 1));
  };

  const getThreatLevel = (count) => {
    if (count >= 20) return { label: "Critical", className: "critical" };
    if (count >= 10) return { label: "High", className: "high" };
    if (count >= 5) return { label: "Medium", className: "medium" };
    return { label: "Low", className: "low" };
  };

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <div className="attack-intelligence-header">
        <h3>Attack Intelligence</h3>
        <span className="attack-intelligence-total">Total Sources: {groups.length}</span>
      </div>

      {groups.length === 0 ? (
        <p>No grouped attack data</p>
      ) : (
        <>
          <div className="attack-intelligence-grid">
            {paginatedGroups.map((g, index) => {
              const threat = getThreatLevel(g.attack_count || 0);

              return (
                <article key={`${g.source_ip}-${index}`} className="attack-intel-card">
                  <div className="attack-intel-card-top">
                    <span className="attack-source-label">Source</span>
                    <span className={`attack-threat ${threat.className}`}>{threat.label}</span>
                  </div>

                  <h4 className="attack-source-ip">{g.source_ip}</h4>

                  <div className="attack-intel-metrics">
                    <div>
                      <p className="metric-label">Total Attacks</p>
                      <p className="metric-value">{g.attack_count || 0}</p>
                    </div>
                    <div>
                      <p className="metric-label">Attack Types</p>
                      <p className="metric-value">{(g.attack_types || []).length}</p>
                    </div>
                  </div>

                  <div className="attack-types-wrap">
                    {(g.attack_types || []).map((typeName) => (
                      <span key={`${g.source_ip}-${typeName}`} className="attack-type-pill">
                        {typeName}
                      </span>
                    ))}
                  </div>
                </article>
              );
            })}
          </div>

          <div className="attack-intelligence-pagination">
            <button
              type="button"
              onClick={goToPrevPage}
              disabled={currentPage === 1}
              className="pagination-btn"
            >
              Previous
            </button>

            <span className="pagination-meta">
              Page {currentPage} of {totalPages}
            </span>

            <button
              type="button"
              onClick={goToNextPage}
              disabled={currentPage === totalPages}
              className="pagination-btn"
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export default GroupedAttacks;