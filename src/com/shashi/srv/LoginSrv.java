@WebServlet("/LoginSrv")
public class LoginSrv extends HttpServlet {
    private static final long serialVersionUID = 1L;

    public LoginSrv() {
        super();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userName = request.getParameter("username");
        String password = request.getParameter("password");
        String userType = request.getParameter("usertype");
        response.setContentType("text/html");

        String status = "Login Denied! Invalid Username or password.";

        if ("admin".equals(userType)) { // Login as Admin

            if (authenticateAdmin(userName, password)) {
                // Valid admin credentials

                RequestDispatcher rd = request.getRequestDispatcher("adminViewProduct.jsp");

                HttpSession session = request.getSession();

                session.setAttribute("username", userName);
                // Do not store the password in session for security reasons
                session.setAttribute("usertype", userType);

                rd.forward(request, response);

            } else {
                // Invalid;
                RequestDispatcher rd = request.getRequestDispatcher("login.jsp?message=" + status);
                rd.include(request, response);
            }

        } else { // Login as customer

            UserServiceImpl udao = new UserServiceImpl();

            status = udao.isValidCredential(userName, password);

            if (status.equalsIgnoreCase("valid")) {
                // Valid user credentials

                UserBean user = udao.getUserDetails(userName, password);

                HttpSession session = request.getSession();

                session.setAttribute("userdata", user);

                session.setAttribute("username", userName);
                // Do not store the password in session for security reasons
                session.setAttribute("usertype", userType);

                RequestDispatcher rd = request.getRequestDispatcher("userHome.jsp");

                rd.forward(request, response);

            } else {
                // Invalid user;

                RequestDispatcher rd = request.getRequestDispatcher("login.jsp?message=" + status);

                rd.forward(request, response);

            }
        }

    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        doGet(request, response);
    }

    private boolean authenticateAdmin(String userName, String password) {
        // Securely compare admin credentials
        String storedAdminPasswordHash = hashPassword("admin");
        return MessageDigest.isEqual(storedAdminPasswordHash.getBytes(), hashPassword(password).getBytes())
                && "admin@gmail.com".equals(userName);
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
}
