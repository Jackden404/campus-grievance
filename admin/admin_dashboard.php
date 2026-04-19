<?php
include "auth.php";
require_admin();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard | Campus Grievance System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="../assets/css/style.css" rel="stylesheet">
</head>
<body class="page-soft-bg">

<nav class="navbar navbar-dark top-nav">
    <div class="container py-2">
        <a href="../index.html" class="navbar-brand fw-semibold">Campus Grievance Portal</a>
        <div class="d-flex gap-2">
            <a href="view_complaints.php" class="btn btn-outline-light btn-sm">View Complaints</a>
            <a href="logout.php" class="btn btn-outline-light btn-sm">Logout</a>
        </div>
    </div>
</nav>

<main class="dash-wrap">
    <div class="container">
        <div class="card hero-card dashboard mb-4 fade-slide">
            <div class="card-body p-4 p-md-5">
                <h1 class="h3 fw-bold mb-2">
                    <i class="bi bi-shield-check me-2" style="opacity:0.7;"></i>Admin Dashboard
                </h1>
                <p class="mb-0 opacity-75">Monitor, prioritize, and resolve campus complaints.</p>
            </div>
        </div>

        <div class="row g-3">
            <div class="col-md-6 col-lg-4">
                <div class="card action-card h-100">
                    <div class="card-body p-4">
                        <div class="mb-2" style="font-size:1.6rem;color:var(--accent);opacity:0.7;">
                            <i class="bi bi-list-ul"></i>
                        </div>
                        <h5 class="fw-bold">All Complaints</h5>
                        <p>Review every submitted complaint in full detail.</p>
                        <a href="view_complaints.php" class="btn btn-primary btn-sm">
                            <i class="bi bi-list-ul me-1"></i> Open List
                        </a>
                    </div>
                </div>
            </div>

            <div class="col-md-6 col-lg-4">
                <div class="card action-card h-100">
                    <div class="card-body p-4">
                        <div class="mb-2" style="font-size:1.6rem;color:var(--accent);opacity:0.7;">
                            <i class="bi bi-kanban"></i>
                        </div>
                        <h5 class="fw-bold">Status Workflow</h5>
                        <p>Update complaint statuses: Pending, In Progress, Resolved.</p>
                        <a href="view_complaints.php" class="btn btn-outline-secondary btn-sm">
                            <i class="bi bi-kanban me-1"></i> Manage Status
                        </a>
                    </div>
                </div>
            </div>

            <div class="col-md-12 col-lg-4">
                <div class="card action-card h-100">
                    <div class="card-body p-4">
                        <div class="mb-2" style="font-size:1.6rem;color:var(--accent);opacity:0.7;">
                            <i class="bi bi-house"></i>
                        </div>
                        <h5 class="fw-bold">Back to User Portal</h5>
                        <p>Return to the main student-facing portal home page.</p>
                        <a href="../index.html" class="btn btn-outline-primary btn-sm">
                            <i class="bi bi-house me-1"></i> Open Home
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</main>

</body>
</html>
