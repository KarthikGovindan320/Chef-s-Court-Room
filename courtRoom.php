<?php

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
        $checkQuery = "SELECT id FROM case_assignments 
                       WHERE case_id = :case_id AND user_id = :user_id";
        $checkStmt = $this->conn->prepare($checkQuery);
        $checkStmt->bindParam(":case_id", $caseId);
        $checkStmt->bindParam(":user_id", $userId);
        $checkStmt->execute();

        if($checkStmt->rowCount() > 0) {
            return false;
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

class Vote {
    private $conn;

    public function __construct($db) {
        $this->conn = $db;
    }

    public function cast($caseId, $userId, $verdict) {
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
        echo json_encode(["error" => "Access denied"]);
        exit();
    }
}

$database = new Database();
$db = $database->getConnection();

$method = $_SERVER['REQUEST_METHOD'];
$request = $_SERVER['REQUEST_URI'];
$path = parse_url($request, PHP_URL_PATH);
$path = str_replace('/api.php', '', $path);

http_response_code(404);
echo json_encode([
    "error" => "Endpoint not found",
    "method" => $method,
    "path" => $path
]);
