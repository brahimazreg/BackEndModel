package com.twd.SpringSecurityJWT.service;

import com.twd.SpringSecurityJWT.dto.ReqRes;
import com.twd.SpringSecurityJWT.entity.User;
import com.twd.SpringSecurityJWT.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTUtils jwtUtils;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;

    public ReqRes signUp(ReqRes registrationRequest){
        ReqRes resp = new ReqRes();
        // check if user already exists in the database

        if(userRepository.findFirstByEmail(registrationRequest.getEmail()).isPresent()){
            resp.setStatusCode(500);
            resp.setError("This user already exits in the database");
            return resp;
        }
            try {
                User user = new User();
                user.setFirstName(registrationRequest.getFirstName());
                user.setLastName(registrationRequest.getLastName());
                user.setEmail(registrationRequest.getEmail());
                user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
                user.setRole("USER");
                User userResult = userRepository.save(user);
                if (userResult != null && userResult.getId() > 0) {
                    resp.setUser(userResult);
                    resp.setMessage("User Saved Successfully");
                    resp.setStatusCode(200);
                }
            } catch (Exception e) {
                resp.setStatusCode(500);
                resp.setError(e.getMessage());
            }
            return resp;
    }

    public ReqRes signIn(ReqRes signinRequest){
        ReqRes response = new ReqRes();

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinRequest.getEmail(),signinRequest.getPassword()));
            var user = userRepository.findByEmail(signinRequest.getEmail()).orElseThrow();
            System.out.println("USER IS: "+ user);
            var jwt = jwtUtils.generateToken(user);
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully Signed In");
            response.setRole(user.getRole());
        }catch (Exception e){
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    public ReqRes refreshToken(ReqRes refreshTokenReqiest){
        ReqRes response = new ReqRes();
        String ourEmail = jwtUtils.extractUsername(refreshTokenReqiest.getToken());
        User users = userRepository.findByEmail(ourEmail).orElseThrow();
        if (jwtUtils.isTokenValid(refreshTokenReqiest.getToken(), users)) {
            var jwt = jwtUtils.generateToken(users);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshTokenReqiest.getToken());
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully Refreshed Token");
        }
        response.setStatusCode(500);
        return response;
    }

    // create adminaccount this method will be called automatically by the constructor.
    @PostConstruct
    public ReqRes createAdminAccount(){
        ReqRes response = new ReqRes();
        User adminAccount = userRepository.findByRole("ADMIN");
        if(adminAccount == null){
            User user = new User();
            user.setFirstName("Brahim");
            user.setLastName("Azreg");
            user.setEmail("admin@gmail.com");
            user.setRole("ADMIN");
            user.setPassword(passwordEncoder.encode("admin"));
            userRepository.save(user);
            response.setMessage("User Saved Successfully");
            response.setStatusCode(200);
       }
        return response;
    }
}
