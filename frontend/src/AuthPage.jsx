import { useMemo, useState } from "react";
import {
  loginUser,
  parseApiError,
  saveAuthSession,
  signupUser,
} from "./services/api";

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const strongPasswordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

const initialSignup = {
  fullName: "",
  email: "",
  password: "",
  confirmPassword: "",
};

const initialLogin = {
  email: "",
  password: "",
};

function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState("signup");
  const [signupData, setSignupData] = useState(initialSignup);
  const [loginData, setLoginData] = useState(initialLogin);
  const [signupErrors, setSignupErrors] = useState({});
  const [loginErrors, setLoginErrors] = useState({});
  const [signupLoading, setSignupLoading] = useState(false);
  const [loginLoading, setLoginLoading] = useState(false);
  const [showSignupPassword, setShowSignupPassword] = useState(false);
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [showSignupConfirmPassword, setShowSignupConfirmPassword] = useState(false);

  const activeTitle = useMemo(
    () =>
      mode === "signup"
        ? "Create your TraceGuard analyst account"
        : "Log in to your TraceGuard dashboard",
    [mode]
  );

  const validateSignup = (payload) => {
    const errors = {};

    if (!payload.fullName.trim()) {
      errors.fullName = "Full name is required.";
    } else if (payload.fullName.trim().length < 2) {
      errors.fullName = "Full name must be at least 2 characters.";
    }

    if (!payload.email.trim()) {
      errors.email = "Email is required.";
    } else if (!emailPattern.test(payload.email.trim())) {
      errors.email = "Enter a valid email address.";
    }

    if (!payload.password) {
      errors.password = "Password is required.";
    } else if (!strongPasswordPattern.test(payload.password)) {
      errors.password = "Use 8+ chars with upper, lower, and a number.";
    }

    if (!payload.confirmPassword) {
      errors.confirmPassword = "Please confirm your password.";
    } else if (payload.password !== payload.confirmPassword) {
      errors.confirmPassword = "Password mismatch.";
    }

    return errors;
  };

  const validateLogin = (payload) => {
    const errors = {};

    if (!payload.email.trim()) {
      errors.email = "Email is required.";
    } else if (!emailPattern.test(payload.email.trim())) {
      errors.email = "Enter a valid email address.";
    }

    if (!payload.password) {
      errors.password = "Password is required.";
    }

    return errors;
  };

  const handleSignupChange = (event) => {
    const { name, value } = event.target;
    setSignupData((prev) => ({
      ...prev,
      [name]: value,
    }));
    setSignupErrors((prev) => ({
      ...prev,
      [name]: "",
    }));
  };

  const handleLoginChange = (event) => {
    const { name, value } = event.target;
    setLoginData((prev) => ({
      ...prev,
      [name]: value,
    }));
    setLoginErrors((prev) => ({
      ...prev,
      [name]: "",
    }));
  };

  const handleSignupSubmit = async (event) => {
    event.preventDefault();
    const errors = validateSignup(signupData);
    const normalizedEmail = signupData.email.trim().toLowerCase();

    setSignupErrors(errors);

    if (Object.keys(errors).length > 0) {
      return;
    }

    setSignupLoading(true);
    try {
      const response = await signupUser({
        full_name: signupData.fullName.trim(),
        email: normalizedEmail,
        password: signupData.password,
      });

      const authData = {
        token: response.data.token,
        user: response.data.user,
        loggedInAt: new Date().toISOString(),
      };
      saveAuthSession(authData);

      setSignupLoading(false);
      onAuthenticated?.({
        mode: "signup",
        ...authData,
      });
    } catch (error) {
      const message = parseApiError(error, "Account creation failed. Please try again.");
      setSignupLoading(false);

      if (message.toLowerCase().includes("email")) {
        setSignupErrors({ email: message });
      } else if (message.toLowerCase().includes("password")) {
        setSignupErrors({ password: message });
      } else if (message.toLowerCase().includes("name")) {
        setSignupErrors({ fullName: message });
      } else {
        setSignupErrors({ form: message });
      }
    }
  };

  const handleLoginSubmit = async (event) => {
    event.preventDefault();
    const errors = validateLogin(loginData);
    setLoginErrors(errors);

    if (Object.keys(errors).length > 0) {
      return;
    }

    setLoginLoading(true);
    try {
      const normalizedEmail = loginData.email.trim().toLowerCase();
      const response = await loginUser({
        email: normalizedEmail,
        password: loginData.password,
      });

      const authData = {
        token: response.data.token,
        user: response.data.user,
        loggedInAt: new Date().toISOString(),
      };
      saveAuthSession(authData);

      setLoginLoading(false);
      onAuthenticated?.({
        mode: "login",
        ...authData,
      });
    } catch (error) {
      const message = parseApiError(error, "Login failed. Please try again.");
      setLoginLoading(false);
      setLoginErrors({ form: message });
    }
  };

  return (
    <div className={`auth-root auth-mode-${mode}`}>
      <div className="auth-orb auth-orb-a" aria-hidden="true" />
      <div className="auth-orb auth-orb-b" aria-hidden="true" />

      <section className="auth-shell">
        <aside className="auth-brand-panel">
          <p className="auth-kicker">TraceGuard Security Platform</p>
          <h1>TraceGuard Access</h1>
          <p>
            Access the TraceGuard dashboard for real-time network threat visibility, forensic context,
            and live intrusion intelligence.
          </p>
        </aside>

        <div className="auth-form-panel">
          <div className="auth-switch" role="tablist" aria-label="Authentication forms">
            <button
              type="button"
              role="tab"
              aria-selected={mode === "login"}
              className={`auth-switch-btn ${mode === "login" ? "active" : ""}`}
              onClick={() => setMode("login")}
            >
              Login
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === "signup"}
              className={`auth-switch-btn ${mode === "signup" ? "active" : ""}`}
              onClick={() => setMode("signup")}
            >
              Sign Up
            </button>
          </div>

          <h2>{activeTitle}</h2>

          <div className="auth-form-stage">
            <form
              className={`auth-form auth-form-login ${mode === "login" ? "active" : "inactive"}`}
              onSubmit={handleLoginSubmit}
              noValidate
            >
              <label htmlFor="login-email">Email address</label>
              <input
                id="login-email"
                name="email"
                type="email"
                value={loginData.email}
                onChange={handleLoginChange}
                placeholder="analyst@company.com"
                required
                autoComplete="email"
              />
              {loginErrors.email ? <p className="field-error">{loginErrors.email}</p> : null}

              <label htmlFor="login-password">Password</label>
              <div className="password-wrap">
                <input
                  id="login-password"
                  name="password"
                  type={showLoginPassword ? "text" : "password"}
                  value={loginData.password}
                  onChange={handleLoginChange}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="toggle-password"
                  onClick={() => setShowLoginPassword((prev) => !prev)}
                >
                  {showLoginPassword ? "Hide" : "Show"}
                </button>
              </div>
              {loginErrors.password ? <p className="field-error">{loginErrors.password}</p> : null}
              {loginErrors.form ? <p className="field-error">{loginErrors.form}</p> : null}

              <button type="submit" className="submit-btn" disabled={loginLoading}>
                {loginLoading ? "Logging in..." : "Login"}
              </button>

              <p className="auth-toggle-copy">
                Don't have an account?{" "}
                <button type="button" className="auth-toggle-link" onClick={() => setMode("signup")}>
                  Sign Up
                </button>
              </p>
            </form>

            <form
              className={`auth-form auth-form-signup ${mode === "signup" ? "active" : "inactive"}`}
              onSubmit={handleSignupSubmit}
              noValidate
            >
              <label htmlFor="signup-name">Full Name</label>
              <input
                id="signup-name"
                name="fullName"
                type="text"
                value={signupData.fullName}
                onChange={handleSignupChange}
                placeholder="Your full name"
                required
                autoComplete="name"
              />
              {signupErrors.fullName ? <p className="field-error">{signupErrors.fullName}</p> : null}

              <label htmlFor="signup-email">Email address</label>
              <input
                id="signup-email"
                name="email"
                type="email"
                value={signupData.email}
                onChange={handleSignupChange}
                placeholder="you@company.com"
                required
                autoComplete="email"
              />
              {signupErrors.email ? <p className="field-error">{signupErrors.email}</p> : null}

              <label htmlFor="signup-password">Password</label>
              <div className="password-wrap">
                <input
                  id="signup-password"
                  name="password"
                  type={showSignupPassword ? "text" : "password"}
                  value={signupData.password}
                  onChange={handleSignupChange}
                  placeholder="Use a strong password"
                  required
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="toggle-password"
                  onClick={() => setShowSignupPassword((prev) => !prev)}
                >
                  {showSignupPassword ? "Hide" : "Show"}
                </button>
              </div>
              {signupErrors.password ? <p className="field-error">{signupErrors.password}</p> : null}

              <label htmlFor="signup-confirm-password">Confirm password</label>
              <div className="password-wrap">
                <input
                  id="signup-confirm-password"
                  name="confirmPassword"
                  type={showSignupConfirmPassword ? "text" : "password"}
                  value={signupData.confirmPassword}
                  onChange={handleSignupChange}
                  placeholder="Confirm your password"
                  required
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="toggle-password"
                  onClick={() => setShowSignupConfirmPassword((prev) => !prev)}
                >
                  {showSignupConfirmPassword ? "Hide" : "Show"}
                </button>
              </div>
              {signupErrors.confirmPassword ? (
                <p className="field-error">{signupErrors.confirmPassword}</p>
              ) : null}
              {signupErrors.form ? <p className="field-error">{signupErrors.form}</p> : null}

              <p className="helper-text">
                Password must be at least 8 characters and include uppercase, lowercase, and a number.
              </p>

              <button type="submit" className="submit-btn" disabled={signupLoading}>
                {signupLoading ? "Creating account..." : "Create Account"}
              </button>

              <p className="auth-toggle-copy">
                Already have an account?{" "}
                <button type="button" className="auth-toggle-link" onClick={() => setMode("login")}>
                  Login
                </button>
              </p>
            </form>
          </div>
        </div>
      </section>
    </div>
  );
}

export default AuthPage;