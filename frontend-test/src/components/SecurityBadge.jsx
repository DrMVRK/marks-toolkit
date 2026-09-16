export default function SecurityBadge({
    label,
    detail,
}) {
    return (
        <div
            className="demo-security-badge"
            title={detail}
        >
            <span className="demo-security-check">
                ✓
            </span>
            <span>{label}</span>
        </div>
    );
}
