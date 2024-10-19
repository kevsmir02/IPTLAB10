<?php 

namespace App\Controllers;

use App\Models\User;

class LoginController extends BaseController {

    public function showLoginForm() {
        // Start session if not already started
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        // Pass an empty remaining_attempts initially
        $data = [
            'remaining_attempts' => null
        ];

        $template = 'login-form';
        return $this->render($template, $data);
    }

    public function login() {
        // Start session if not already started
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $username = $_POST['username'] ?? null;
            $password = $_POST['password'] ?? null;

            if (empty($username) || empty($password)) {
                $errors[] = "Username and password are required.";
                return $this->showLoginFormWithErrors($errors);
            }

            // Initialize User model and fetch password hash
            $user = new User();
            $saved_password_hash = $user->getPassword($username);

            if ($saved_password_hash && password_verify($password, $saved_password_hash)) {
                // Reset login attempts on successful login
                $_SESSION['login_attempts'] = 0;

                // Store session data
                $_SESSION['is_logged_in'] = true;
                $_SESSION['username'] = $username;

                // Redirect to welcome page
                header("Location: /welcome");
                exit;
            } else {
                // Increment failed login attempts
                $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;

                // Get remaining attempts
                $max_attempts = 3;
                $remaining_attempts = $max_attempts - $_SESSION['login_attempts'];

                if ($_SESSION['login_attempts'] >= $max_attempts) {
                    $errors[] = "Too many failed login attempts. Please try again later.";
                    return $this->render('login-form', ['errors' => $errors, 'form_disabled' => true]);
                } else {
                    $errors[] = "Invalid username or password. Attempts remaining: $remaining_attempts.";
                    return $this->showLoginFormWithErrors($errors, $remaining_attempts);
                }
            }
        } else {
            return $this->showLoginForm();
        }
    }

    private function showLoginFormWithErrors($errors, $remaining_attempts = null) {
        // Pass remaining attempts if provided
        return $this->render('login-form', [
            'errors' => $errors,
            'remaining_attempts' => $remaining_attempts
        ]);
    }

    public function logout() {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        session_destroy();
        header("Location: /login-form");
        exit;
    }
}