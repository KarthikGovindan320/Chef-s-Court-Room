<?php
/*
My interpretation of the original question : 
  1) I didnt allow the judge to edit aurguments, because when would that ever be warranted ?
  2) There is an admin user who assigns roles to the people in the court room (like judge, defendent ect). Beacuse letting users choose their role is a bit unnatural. 
     So, an admin sets up the court room, and then the case proceeds as normal
*/

/*
 * CHEF'S COURT OF JUSTICE - Complete Backend API (Admin-Managed System)
 * 
 * Setup Instructions:
 * 1. Install Composer: composer require firebase/php-jwt
 * 2. Create database using the SQL below
 * 3. Update database credentials in Database class
 * 4. Place this file in your web server (e.g., /var/www/html/api.php)
 * 5. Default Admin Account: admin@court.com / admin123 (created via SQL)
*/

/*
SQL DATABASE SETUP:

CREATE DATABASE karthik_court;
USE karthik_court;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'judge', 'defendant', 'plaintiff', 'juror', 'prosecutor') NOT NULL,
    created_by INT DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Insert default admin account (password: admin123)
INSERT INTO users (username, email, password, role, is_active) 
VALUES ('admin', 'admin@court.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', TRUE);

CREATE TABLE cases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_number VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    judge_id INT NOT NULL,
    status ENUM('created', 'in_progress', 'voting', 'closed') DEFAULT 'created',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    FOREIGN KEY (judge_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE case_assignments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    user_id INT NOT NULL,
    role ENUM('judge', 'defendant', 'plaintiff', 'juror', 'prosecutor') NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_case_user (case_id, user_id)
);

CREATE TABLE submissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    user_id INT NOT NULL,
    submission_type ENUM('argument', 'evidence', 'rebuttal') NOT NULL,
    content TEXT NOT NULL,
    document_path VARCHAR(255),
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE votes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    user_id INT NOT NULL,
    verdict ENUM('guilty', 'not_guilty') NOT NULL,
    voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_vote (case_id, user_id)
);
*/

// Headers
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

define('SECRET_KEY', 'your_secret_key_change_in_production_12345');

// ============================================================================
// DATABASE CLASS
// ============================================================================
class Database {
    private $host = "localhost";
    private $db_name = "karthik_court";
    private $username = "karthik";
    private $password = "place-holder-pass";
    public $conn;

    public function getConnection() {
        $this->conn = null;
        try {
            $this->conn = new PDO(
                "mysql:host=" . $this->host . ";dbname=" . $this->db_name,
                $this->username,
                $this->password
            );
            $this->conn->exec("set names utf8");
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch(PDOException $e) {
            http_response_code(500);
            echo json_encode(["error" => "Database connection failed"]);
            exit();
        }
        return $this->conn;
    }
}

// ============================================================================
// USER MODEL
// ============================================================================
class User {
    private $conn;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($username, $email, $password, $role, $createdBy) {
        $query = "INSERT INTO users (username, email, password, role, created_by, is_active) 
                  VALUES (:username, :email, :password, :role, :created_by, TRUE)";
        $stmt = $this->conn->prepare($query);
        
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        
        $stmt->bindParam(":username", $username);
        $stmt->bindParam(":email", $email);
        $stmt->bindParam(":password", $hashedPassword);
        $stmt->bindParam(":role", $role);
        $stmt->bindParam(":created_by", $createdBy);

        if($stmt->execute()) {
            return $this->conn->lastInsertId();
        }
        return false;
    }

    public function login($email, $password) {
        $query = "SELECT id, username, email, password, role, is_active 
                  FROM users WHERE email = :email LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":email", $email);
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if($row && $row['is_active'] && password_verify($password, $row['password'])) {
            return [
                'id' => $row['id'],
                'username' => $row['username'],
                'email' => $row['email'],
                'role' => $row['role']
            ];
        }
        return false;
    }

    public function getAll() {
        $query = "SELECT id, username, email, role, is_active, created_at 
                  FROM users ORDER BY created_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getByRole($role) {
        $query = "SELECT id, username, email, role, is_active 
                  FROM users WHERE role = :role AND is_active = TRUE 
                  ORDER BY username";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":role", $role);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function updateStatus($userId, $isActive) {
        $query = "UPDATE users SET is_active = :is_active WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":is_active", $isActive, PDO::PARAM_BOOL);
        $stmt->bindParam(":id", $userId);
        return $stmt->execute();
    }

    public function delete($userId) {
        $query = "DELETE FROM users WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $userId);
        return $stmt->execute();
    }
}

// ============================================================================
// CASE MODEL
// ============================================================================
class CaseModel {
    private $conn;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($caseNumber, $title, $description, $judgeId) {
        $query = "INSERT INTO cases (case_number, title, description, judge_id, status) 
                  VALUES (:case_number, :title, :description, :judge_id, 'created')";
        $stmt = $this->conn->prepare($query);
        
        $stmt->bindParam(":case_number", $caseNumber);
        $stmt->bindParam(":title", $title);
        $stmt->bindParam(":description", $description);
        $stmt->bindParam(":judge_id", $judgeId);

        if($stmt->execute()) {
            return $this->conn->lastInsertId();
        }
        return false;
    }

    public function assignUser($caseId, $userId, $role) {
        // Check if user is already assigned
        $checkQuery = "SELECT id FROM case_assignments 
                       WHERE case_id = :case_id AND user_id = :user_id";
        $checkStmt = $this->conn->prepare($checkQuery);
        $checkStmt->bindParam(":case_id", $caseId);
        $checkStmt->bindParam(":user_id", $userId);
        $checkStmt->execute();
        
        if($checkStmt->rowCount() > 0) {
            return false; // Already assigned
        }

        $query = "INSERT INTO case_assignments (case_id, user_id, role) 
                  VALUES (:case_id, :user_id, :role)";
        $stmt = $this->conn->prepare($query);
        
        $stmt->bindParam(":case_id", $caseId);
        $stmt->bindParam(":user_id", $userId);
        $stmt->bindParam(":role", $role);

        return $stmt->execute();
    }

    public function removeAssignment($caseId, $userId) {
        $query = "DELETE FROM case_assignments 
                  WHERE case_id = :case_id AND user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":case_id", $caseId);
        $stmt->bindParam(":user_id", $userId);
        return $stmt->execute();
    }

    public function getAll() {
        $query = "SELECT c.*, u.username as judge_name,
                  (SELECT COUNT(*) FROM case_assignments ca WHERE ca.case_id = c.id) as assigned_count
                  FROM cases c 
                  LEFT JOIN users u ON c.judge_id = u.id 
                  ORDER BY c.created_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getById($caseId) {
        $query = "SELECT c.*, u.username as judge_name 
                  FROM cases c 
                  LEFT JOIN users u ON c.judge_id = u.id 
                  WHERE c.id = :id LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $caseId);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getAssignments($caseId) {
        $query = "SELECT ca.*, u.username, u.email 
                  FROM case_assignments ca 
                  LEFT JOIN users u ON ca.user_id = u.id 
                  WHERE ca.case_id = :case_id 
                  ORDER BY ca.role";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":case_id", $caseId);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getMyCases($userId) {
        $query = "SELECT DISTINCT c.*, u.username as judge_name, ca.role as my_role
                  FROM cases c 
                  LEFT JOIN users u ON c.judge_id = u.id 
                  INNER JOIN case_assignments ca ON c.id = ca.case_id 
                  WHERE ca.user_id = :user_id 
                  ORDER BY c.created_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $userId);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function isUserAssigned($caseId, $userId) {
        $query = "SELECT role FROM case_assignments 
                  WHERE case_id = :case_id AND user_id = :user_id LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":case_id", $caseId);
        $stmt->bindParam(":user_id", $userId);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['role'] : false;
    }

    public function updateStatus($caseId, $status) {
        $query = "UPDATE cases SET status = :status WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":status", $status);
        $stmt->bindParam(":id", $caseId);
        return $stmt->execute();
    }

    public function delete($caseId) {
        $query = "DELETE FROM cases WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $caseId);
        return $stmt->execute();
    }
}

// ============================================================================
// SUBMISSION MODEL
// ============================================================================
class Submission {
    private $conn;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function create($caseId, $userId, $type, $content, $documentPath) {
        $query = "INSERT INTO submissions (case_id, user_id, submission_type, content, document_path) 
                  VALUES (:case_id, :user_id, :type, :content, :document_path)";
        $stmt = $this->conn->prepare($query);
        
        $stmt->bindParam(":case_id", $caseId);
        $stmt->bindParam(":user_id", $userId);
        $stmt->bindParam(":type", $type);
        $stmt->bindParam(":content", $content);
        $stmt->bindParam(":document_path", $documentPath);

        if($stmt->execute()) {
            return $this->conn->lastInsertId();
        }
        return false;
    }

    public function getByCase($caseId) {
        $query = "SELECT s.*, u.username, u.role as user_role 
                  FROM submissions s 
                  LEFT JOIN users u ON s.user_id = u.id 
                  WHERE s.case_id = :case_id 
                  ORDER BY s.submitted_at ASC";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":case_id", $caseId);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function delete($submissionId) {
        $query = "DELETE FROM submissions WHERE id = :id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $submissionId);
        return $stmt->execute();
    }
}

// ============================================================================
// VOTE MODEL
// ============================================================================
class Vote {
    private $conn;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function cast($caseId, $userId, $verdict) {
        // Check if already voted
        $checkQuery = "SELECT id FROM votes 
                       WHERE case_id = :case_id AND user_id = :user_id";
        $checkStmt = $this->conn->prepare($checkQuery);
        $checkStmt->bindParam(":case_id", $caseId);
        $checkStmt->bindParam(":user_id", $userId);
        $checkStmt->execute();
        
        if($checkStmt->rowCount() > 0) {
            return false;
        }

        $query = "INSERT INTO votes (case_id, user_id, verdict) 
                  VALUES (:case_id, :user_id, :verdict)";
        $stmt = $this->conn->prepare($query);
        
        $stmt->bindParam(":case_id", $caseId);
        $stmt->bindParam(":user_id", $userId);
        $stmt->bindParam(":verdict", $verdict);

        return $stmt->execute();
    }

    public function getResults($caseId) {
        $query = "SELECT verdict, COUNT(*) as count 
                  FROM votes 
                  WHERE case_id = :case_id 
                  GROUP BY verdict";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":case_id", $caseId);
        $stmt->execute();
        
        $results = ['guilty' => 0, 'not_guilty' => 0];
        while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $results[$row['verdict']] = (int)$row['count'];
        }
        return $results;
    }
}

// ============================================================================
// AUTH HELPERS
// ============================================================================
function generateToken($userId, $username, $role) {
    $payload = [
        'iss' => 'karthik_court',
        'iat' => time(),
        'exp' => time() + (60 * 60 * 24),
        'user_id' => $userId,
        'username' => $username,
        'role' => $role
    ];
    return JWT::encode($payload, SECRET_KEY, 'HS256');
}

function authenticate() {
    $headers = getallheaders();
    if(!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "No token provided"]);
        exit();
    }

    $token = str_replace('Bearer ', '', $headers['Authorization']);
    
    try {
        return JWT::decode($token, new Key(SECRET_KEY, 'HS256'));
    } catch(Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
        exit();
    }
}

function checkRole($user, $allowedRoles) {
    if(!in_array($user->role, $allowedRoles)) {
        http_response_code(403);
        echo json_encode(["error" => "Access denied. Required roles: " . implode(', ', $allowedRoles)]);
        exit();
    }
}

// ============================================================================
// ROUTING
// ============================================================================
$database = new Database();
$db = $database->getConnection();

$method = $_SERVER['REQUEST_METHOD'];
$request = $_SERVER['REQUEST_URI'];
$path = parse_url($request, PHP_URL_PATH);
$path = str_replace('/api.php', '', $path);

// ============================================================================
// AUTH ROUTES
// ============================================================================

// POST /auth/login
if ($method === 'POST' && $path === '/auth/login') {
    $data = json_decode(file_get_contents("php://input"));
    
    if(!empty($data->email) && !empty($data->password)) {
        $user = new User($db);
        $userData = $user->login($data->email, $data->password);

        if($userData) {
            $token = generateToken($userData['id'], $userData['username'], $userData['role']);
            
            http_response_code(200);
            echo json_encode([
                "success" => true,
                "message" => "Login successful",
                "token" => $token,
                "user" => $userData
            ]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Invalid credentials or account inactive"]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Missing email or password"]);
    }
    exit();
}

// ============================================================================
// ADMIN ROUTES - User Management
// ============================================================================

// POST /admin/users/create
if ($method === 'POST' && $path === '/admin/users/create') {
    $user_auth = authenticate();
    checkRole($user_auth, ['admin']);
    
    $data = json_decode(file_get_contents("php://input"));
    
    if(!empty($data->username) && !empty($data->email) && !empty($data->password) && !empty($data->role)) {
        $validRoles = ['judge', 'defendant', 'plaintiff', 'juror', 'prosecutor'];
        if(!in_array($data->role, $validRoles)) {
            http_response_code(400);
            echo json_encode(["error" => "Invalid role"]);
            exit();
        }

        $user = new User($db);
        $userId = $user->create($data->username, $data->email, $data->password, $data->role, $user_auth->user_id);
        
        if($userId) {
            http_response_code(201);
            echo json_encode([
                "success" => true,
                "message" => "User created successfully",
                "user_id" => $userId,
                "username" => $data->username,
                "role" => $data->role
            ]);
        } else {
            http_response_code(503);
            echo json_encode(["error" => "Unable to create user. Email or username may exist."]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Missing required fields"]);
    }
    exit();
}

// GET /admin/users
if ($method === 'GET' && $path === '/admin/users') {
    $user_auth = authenticate();
    checkRole($user_auth, ['admin']);
    
    $user = new User($db);
    $users = $user->getAll();
    
    http_response_code(200);
    echo json_encode([
        "success" => true,
        "count" => count($users),
        "users" => $users
    ]);
    exit();
}

// PATCH /admin/users/{id}/status
if ($method === 'PATCH' && preg_match('#^/admin/users/(\d+)/status$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['admin']);
    
    $userId = $matches[1];
    $data = json_decode(file_get_contents("php://input"));
    
    if(isset($data->is_active)) {
        $user = new User($db);
        if($user->updateStatus($userId, $data->is_active)) {
            http_response_code(200);
            echo json_encode([
                "success" => true,
                "message" => "User status updated",
                "user_id" => $userId,
                "is_active" => $data->is_active
            ]);
        } else {
            http_response_code(503);
            echo json_encode(["error" => "Unable to update status"]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Missing is_active field"]);
    }
    exit();
}

// DELETE /admin/users/{id}
if ($method === 'DELETE' && preg_match('#^/admin/users/(\d+)$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['admin']);
    
    $userId = $matches[1];
    $user = new User($db);
    
    if($user->delete($userId)) {
        http_response_code(200);
        echo json_encode([
            "success" => true,
            "message" => "User deleted successfully"
        ]);
    } else {
        http_response_code(503);
        echo json_encode(["error" => "Unable to delete user"]);
    }
    exit();
}

// GET /admin/users/by-role/{role}
if ($method === 'GET' && preg_match('#^/admin/users/by-role/(.+)$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['admin', 'judge']);
    
    $role = $matches[1];
    $user = new User($db);
    $users = $user->getByRole($role);
    
    http_response_code(200);
    echo json_encode([
        "success" => true,
        "role" => $role,
        "count" => count($users),
        "users" => $users
    ]);
    exit();
}

// ============================================================================
// JUDGE ROUTES - Case Management
// ============================================================================

// POST /judge/cases/create
if ($method === 'POST' && $path === '/judge/cases/create') {
    $user_auth = authenticate();
    checkRole($user_auth, ['judge']);
    
    $data = json_decode(file_get_contents("php://input"));
    
    if(!empty($data->case_number) && !empty($data->title)) {
        $case = new CaseModel($db);
        $caseId = $case->create(
            $data->case_number,
            $data->title,
            $data->description ?? '',
            $user_auth->user_id
        );
        
        if($caseId) {
            http_response_code(201);
            echo json_encode([
                "success" => true,
                "message" => "Case created successfully",
                "case_id" => $caseId,
                "case_number" => $data->case_number
            ]);
        } else {
            http_response_code(503);
            echo json_encode(["error" => "Unable to create case. Case number may exist."]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Missing case_number or title"]);
    }
    exit();
}

// POST /judge/cases/{caseId}/assign
if ($method === 'POST' && preg_match('#^/judge/cases/(\d+)/assign$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['judge']);
    
    $caseId = $matches[1];
    $data = json_decode(file_get_contents("php://input"));
    
    if(!empty($data->user_id) && !empty($data->role)) {
        $case = new CaseModel($db);
        
        if($case->assignUser($caseId, $data->user_id, $data->role)) {
            http_response_code(201);
            echo json_encode([
                "success" => true,
                "message" => "User assigned to case",
                "case_id" => $caseId,
                "user_id" => $data->user_id,
                "role" => $data->role
            ]);
        } else {
            http_response_code(400);
            echo json_encode(["error" => "User already assigned or assignment failed"]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Missing user_id or role"]);
    }
    exit();
}

// DELETE /judge/cases/{caseId}/assign/{userId}
if ($method === 'DELETE' && preg_match('#^/judge/cases/(\d+)/assign/(\d+)$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['judge']);
    
    $caseId = $matches[1];
    $userId = $matches[2];
    $case = new CaseModel($db);
    
    if($case->removeAssignment($caseId, $userId)) {
        http_response_code(200);
        echo json_encode([
            "success" => true,
            "message" => "User removed from case"
        ]);
    } else {
        http_response_code(503);
        echo json_encode(["error" => "Unable to remove assignment"]);
    }
    exit();
}

// PATCH /judge/cases/{caseId}/status
if ($method === 'PATCH' && preg_match('#^/judge/cases/(\d+)/status$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['judge']);
    
    $caseId = $matches[1];
    $data = json_decode(file_get_contents("php://input"));
    
    if(!empty($data->status)) {
        $validStatuses = ['created', 'in_progress', 'voting', 'closed'];
        if(!in_array($data->status, $validStatuses)) {
            http_response_code(400);
            echo json_encode(["error" => "Invalid status"]);
            exit();
        }

        $case = new CaseModel($db);
        if($case->updateStatus($caseId, $data->status)) {
            http_response_code(200);
            echo json_encode([
                "success" => true,
                "message" => "Case status updated",
                "case_id" => $caseId,
                "status" => $data->status
            ]);
        } else {
            http_response_code(503);
            echo json_encode(["error" => "Unable to update status"]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Missing status field"]);
    }
    exit();
}

// DELETE /judge/cases/{caseId}
if ($method === 'DELETE' && preg_match('#^/judge/cases/(\d+)$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['judge']);
    
    $caseId = $matches[1];
    $case = new CaseModel($db);
    
    if($case->delete($caseId)) {
        http_response_code(200);
        echo json_encode([
            "success" => true,
            "message" => "Case deleted successfully"
        ]);
    } else {
        http_response_code(503);
        echo json_encode(["error" => "Unable to delete case"]);
    }
    exit();
}

// ============================================================================
// CASE ROUTES - View Cases
// ============================================================================

// GET /cases
if ($method === 'GET' && $path === '/cases') {
    $user_auth = authenticate();
    
    $case = new CaseModel($db);
    
    if($user_auth->role === 'admin' || $user_auth->role === 'judge') {
        $cases = $case->getAll();
    } else {
        $cases = $case->getMyCases($user_auth->user_id);
    }
    
    http_response_code(200);
    echo json_encode([
        "success" => true,
        "count" => count($cases),
        "cases" => $cases
    ]);
    exit();
}

// GET /cases/{caseId}
if ($method === 'GET' && preg_match('#^/cases/(\d+)$#', $path, $matches)) {
    $user_auth = authenticate();
    
    $caseId = $matches[1];
    $case = new CaseModel($db);
    
    // Check if user has access to this case
    if($user_auth->role !== 'admin' && $user_auth->role !== 'judge') {
        $userRole = $case->isUserAssigned($caseId, $user_auth->user_id);
        if(!$userRole) {
            http_response_code(403);
            echo json_encode(["error" => "You are not assigned to this case"]);
            exit();
        }
    }
    
    $caseData = $case->getById($caseId);
    $assignments = $case->getAssignments($caseId);
    
    if($caseData) {
        http_response_code(200);
        echo json_encode([
            "success" => true,
            "case" => $caseData,
            "assignments" => $assignments
        ]);
    } else {
        http_response_code(404);
        echo json_encode(["error" => "Case not found"]);
    }
    exit();
}

// ============================================================================
// SUBMISSION ROUTES
// ============================================================================

// POST /cases/{caseId}/submit
if ($method === 'POST' && preg_match('#^/cases/(\d+)/submit$#', $path, $matches)) {
    $user_auth = authenticate();
    
    $caseId = $matches[1];
    $case = new CaseModel($db);
    
    // Check if user is assigned to this case
    $userRole = $case->isUserAssigned($caseId, $user_auth->user_id);
    if(!$userRole) {
        http_response_code(403);
        echo json_encode(["error" => "You are not assigned to this case"]);
        exit();
    }
    
    $data = json_decode(file_get_contents("php://input"));
    
    if(!empty($data->type) && !empty($data->content)) {
        $validTypes = ['argument', 'evidence', 'rebuttal'];
        if(!in_array($data->type, $validTypes)) {
            http_response_code(400);
            echo json_encode(["error" => "Invalid submission type"]);
            exit();
        }

        $submission = new Submission($db);
        $submissionId = $submission->create(
            $caseId,
            $user_auth->user_id,
            $data->type,
            $data->content,
            $data->document_path ?? null
        );
        
        if($submissionId) {
            http_response_code(201);
            echo json_encode([
                "success" => true,
                "message" => "Submission added successfully",
                "submission_id" => $submissionId,
                "type" => $data->type
            ]);
        } else {
            http_response_code(503);
            echo json_encode(["error" => "Unable to create submission"]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Missing type or content"]);
    }
    exit();
}

// GET /cases/{caseId}/submissions
if ($method === 'GET' && preg_match('#^/cases/(\d+)/submissions$#', $path, $matches)) {
    $user_auth = authenticate();
    
    $caseId = $matches[1];
    $case = new CaseModel($db);
    
    // Check access
    if($user_auth->role !== 'admin' && $user_auth->role !== 'judge') {
        $userRole = $case->isUserAssigned($caseId, $user_auth->user_id);
        if(!$userRole) {
            http_response_code(403);
            echo json_encode(["error" => "You are not assigned to this case"]);
            exit();
        }
    }
    
    $submission = new Submission($db);
    $submissions = $submission->getByCase($caseId);
    
    http_response_code(200);
    echo json_encode([
        "success" => true,
        "case_id" => $caseId,
        "count" => count($submissions),
        "submissions" => $submissions
    ]);
    exit();
}

// DELETE /submissions/{submissionId}
if ($method === 'DELETE' && preg_match('#^/submissions/(\d+)$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['judge']);
    
    $submissionId = $matches[1];
    $submission = new Submission($db);
    
    if($submission->delete($submissionId)) {
        http_response_code(200);
        echo json_encode([
            "success" => true,
            "message" => "Submission deleted successfully"
        ]);
    } else {
        http_response_code(503);
        echo json_encode(["error" => "Unable to delete submission"]);
    }
    exit();
}

// ============================================================================
// VOTING ROUTES
// ============================================================================

// POST /cases/{caseId}/vote
if ($method === 'POST' && preg_match('#^/cases/(\d+)/vote$#', $path, $matches)) {
    $user_auth = authenticate();
    checkRole($user_auth, ['juror']);
    
    $caseId = $matches[1];
    $case = new CaseModel($db);
    
    // Check if juror is assigned to this case
    $userRole = $case->isUserAssigned($caseId, $user_auth->user_id);
    if($userRole !== 'juror') {
        http_response_code(403);
        echo json_encode(["error" => "You are not assigned as a juror to this case"]);
        exit();
    }
    
    // Check if case is in voting status
    $caseData = $case->getById($caseId);
    if($caseData['status'] !== 'voting') {
        http_response_code(400);
        echo json_encode(["error" => "Case is not open for voting. Current status: " . $caseData['status']]);
        exit();
    }
    
    $data = json_decode(file_get_contents("php://input"));
    
    if(!empty($data->verdict) && in_array($data->verdict, ['guilty', 'not_guilty'])) {
        $vote = new Vote($db);
        
        if($vote->cast($caseId, $user_auth->user_id, $data->verdict)) {
            http_response_code(201);
            echo json_encode([
                "success" => true,
                "message" => "Vote cast successfully",
                "case_id" => $caseId,
                "verdict" => $data->verdict
            ]);
        } else {
            http_response_code(400);
            echo json_encode(["error" => "You have already voted on this case"]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Invalid verdict. Must be 'guilty' or 'not_guilty'"]);
    }
    exit();
}

// GET /cases/{caseId}/results
if ($method === 'GET' && preg_match('#^/cases/(\d+)/results$#', $path, $matches)) {
    $user_auth = authenticate();
    
    $caseId = $matches[1];
    $case = new CaseModel($db);
    
    // Check access
    if($user_auth->role !== 'admin' && $user_auth->role !== 'judge') {
        $userRole = $case->isUserAssigned($caseId, $user_auth->user_id);
        if(!$userRole) {
            http_response_code(403);
            echo json_encode(["error" => "You are not assigned to this case"]);
            exit();
        }
    }
    
    $vote = new Vote($db);
    $results = $vote->getResults($caseId);
    
    $totalVotes = $results['guilty'] + $results['not_guilty'];
    $verdict = null;
    
    if($totalVotes > 0) {
        $verdict = $results['guilty'] > $results['not_guilty'] ? 'guilty' : 'not_guilty';
    }
    
    http_response_code(200);
    echo json_encode([
        "success" => true,
        "case_id" => $caseId,
        "results" => $results,
        "total_votes" => $totalVotes,
        "verdict" => $verdict
    ]);
    exit();
}

// ============================================================================
// 404 - Route not found
// ============================================================================
http_response_code(404);
echo json_encode([
    "error" => "Endpoint not found",
    "method" => $method,
    "path" => $path
]);
?>
