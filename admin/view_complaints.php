<?php
include "auth.php";
require_admin();
include "../php/connect.php";
include "../php/csrf.php";

$csrf_token = csrf_token();

$sql = "SELECT * FROM complaints";
$result = mysqli_query($conn, $sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - View Complaints</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="../assets/css/style.css" rel="stylesheet">
</head>
<body class="page-soft-bg">

<nav class="navbar navbar-dark top-nav">
    <div class="container py-2">
        <a href="../index.html" class="navbar-brand fw-semibold">Campus Grievance Portal</a>
        <div class="d-flex gap-2">
            <a href="admin_dashboard.php" class="btn btn-outline-light btn-sm">Dashboard</a>
            <a href="logout.php" class="btn btn-outline-light btn-sm">Logout</a>
        </div>
    </div>
</nav>

<main class="py-4">
    <div class="container">
        <div class="d-flex flex-wrap justify-content-between align-items-center mb-3">
            <h3 class="mb-2 mb-md-0">
                <i class="bi bi-list-ul me-2" style="color:var(--accent);"></i>All Complaints
            </h3>
            <a href="admin_dashboard.php" class="btn btn-outline-secondary btn-sm">
                <i class="bi bi-arrow-left me-1"></i> Back
            </a>
        </div>

        <div class="card card-soft">
            <div class="card-body p-3 p-md-4">
                <div class="table-responsive">
                    <table class="table admin-table table-bordered align-middle mb-0">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>User Email</th>
                                <th>Category</th>
                                <th>Description</th>
                                <th>Attachment</th>
                                <th>Status / Actions</th>
                            </tr>
                        </thead>

                        <tbody>
                        <?php
                        if (mysqli_num_rows($result) > 0) {
                            while ($row = mysqli_fetch_assoc($result)) {
                                $id = (int)$row['id'];
                                $user_email = htmlspecialchars($row['user_email']);
                                $category = htmlspecialchars($row['category']);
                                $description = htmlspecialchars($row['description']);
                                $status = htmlspecialchars($row['status']);

                                $attachment_cell = "<span class='text-muted small'>No file</span>";
                                if (isset($row['attachment']) && !empty($row['attachment'])) {
                                    $file_path = htmlspecialchars("../" . ltrim($row['attachment'], '/'));
                                    $attachment_cell = "<button type='button' class='btn btn-outline-primary btn-sm view-file-btn' data-file='" . $file_path . "'>View</button>";
                                }

                                echo "<tr>";
                                echo "<td>" . $id . "</td>";
                                echo "<td>" . $user_email . "</td>";
                                echo "<td>" . $category . "</td>";
                                echo "<td>" . $description . "</td>";
                                echo "<td>" . $attachment_cell . "</td>";
                                echo "<td>
                                <form action='update_status.php' method='post' class='d-grid gap-2 mb-2'>
                                    <input type='hidden' name='id' value='" . $id . "'>
                                    <input type='hidden' name='csrf_token' value='" . htmlspecialchars($csrf_token) . "'>
                                    <select name='status' class='form-select form-select-sm status-select'>
                                        <option value='Pending' " . ($status === "Pending" ? "selected" : "") . ">Pending</option>
                                        <option value='In Progress' " . ($status === "In Progress" ? "selected" : "") . ">In Progress</option>
                                        <option value='Resolved' " . ($status === "Resolved" ? "selected" : "") . ">Resolved</option>
                                        <option value='Rejected' " . ($status === "Rejected" ? "selected" : "") . ">Rejected</option>
                                    </select>
                                    <button type='submit' class='btn btn-primary btn-sm'>Update</button>
                                </form>

                                <form action='delete_complaint.php' method='post' class='delete-complaint-form' data-id='" . $id . "'>
                                    <input type='hidden' name='id' value='" . $id . "'>
                                    <input type='hidden' name='csrf_token' value='" . htmlspecialchars($csrf_token) . "'>
                                    <button type='submit' class='btn btn-outline-danger btn-sm w-100'>Delete</button>
                                </form>
                                </td>";
                                echo "</tr>";
                            }
                        } else {
                            echo "<tr><td colspan='6' class='text-center text-muted'>No complaints found.</td></tr>";
                        }
                        ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</main>

<div class="modal fade" id="attachmentModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Complaint Attachment</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div id="attachmentFallback" class="d-none">
                    <p class="text-muted mb-3">Preview unavailable.</p>
                    <a id="downloadAttachmentLink" href="#" class="btn btn-primary" target="_blank" rel="noopener">Open File</a>
                </div>
                <img id="attachmentImage" class="img-fluid d-none" alt="Attachment preview">
                <iframe id="attachmentPdf" class="w-100 d-none" style="min-height: 70vh; border: 0;" title="Attachment Preview"></iframe>
            </div>
            <div class="modal-footer">
                <a id="openInNewTabBtn" href="#" target="_blank" rel="noopener" class="btn btn-outline-primary">Open New Tab</a>
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
const attachmentModalEl = document.getElementById("attachmentModal");
const attachmentModal = new bootstrap.Modal(attachmentModalEl);
const imagePreview = document.getElementById("attachmentImage");
const pdfPreview = document.getElementById("attachmentPdf");
const fallbackPreview = document.getElementById("attachmentFallback");
const openInNewTabBtn = document.getElementById("openInNewTabBtn");
const downloadAttachmentLink = document.getElementById("downloadAttachmentLink");
const viewButtons = document.querySelectorAll(".view-file-btn");
const deleteForms = document.querySelectorAll(".delete-complaint-form");

function resetPreview() {
    imagePreview.classList.add("d-none");
    pdfPreview.classList.add("d-none");
    fallbackPreview.classList.add("d-none");
    imagePreview.removeAttribute("src");
    pdfPreview.removeAttribute("src");
}

viewButtons.forEach((button) => {
    button.addEventListener("click", () => {
        const fileUrl = button.getAttribute("data-file");
        const lower = fileUrl.toLowerCase();

        resetPreview();
        openInNewTabBtn.href = fileUrl;
        downloadAttachmentLink.href = fileUrl;

        if (lower.endsWith(".pdf")) {
            pdfPreview.src = fileUrl;
            pdfPreview.classList.remove("d-none");
        } else if (lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".png")) {
            imagePreview.src = fileUrl;
            imagePreview.classList.remove("d-none");
        } else {
            fallbackPreview.classList.remove("d-none");
        }

        attachmentModal.show();
    });
});

attachmentModalEl.addEventListener("hidden.bs.modal", resetPreview);

deleteForms.forEach((form) => {
    form.addEventListener("submit", (event) => {
        const complaintId = form.getAttribute("data-id");
        const confirmed = confirm(`Delete complaint #${complaintId}? This action cannot be undone.`);
        if (!confirmed) {
            event.preventDefault();
        }
    });
});
</script>

</body>
</html>
