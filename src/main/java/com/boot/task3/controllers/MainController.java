package com.boot.task3.controllers;

import com.boot.task3.entities.Comment;
import com.boot.task3.entities.Post;
import com.boot.task3.entities.Roles;
import com.boot.task3.entities.Users;
import com.boot.task3.repositories.CommentRepository;
import com.boot.task3.repositories.PostRepository;
import com.boot.task3.repositories.RoleRepository;
import com.boot.task3.repositories.UserRepository;
import com.boot.task3.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

@Controller
public class MainController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PostRepository postRepository;
    private final CommentRepository commentRepository;
    private final UserService userService;

    @Autowired
    MainController(UserRepository userRepository,
                   RoleRepository roleRepository,
                   PostRepository postRepository,
                   CommentRepository commentRepository,
                   UserService userService){
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.postRepository = postRepository;
        this.commentRepository = commentRepository;
        this.userService = userService;
    }


    @GetMapping(path = "/")
    public String index(Model model, @RequestParam(name = "key", defaultValue = "", required = false) String key){
        List<Post> posts = postRepository.findAll();
        model.addAttribute("posts", posts);
        return "index";
    }

    @GetMapping(path = "/users")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String users(Model model){
        List<Users> users = userRepository.findAllByRolesIsNotContainingAndRolesIsNotContaining(
                roleRepository.getOne(1L), roleRepository.getOne(3L));
        model.addAttribute("users", users);
        return "users";
    }

    @GetMapping(path = "/manageUsers")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String manageUsers(Model model){
        List<Users> users = userRepository.findAllByRolesIsNotContaining(roleRepository.getOne(1L));
        model.addAttribute("users", users);
        return "manageUsers";
    }

    @GetMapping(path = "/addPost")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String addPostPage(Model model){
        model.addAttribute("user", getUserData());
        return "addPost";
    }

    @PostMapping(path = "/addNewPost")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String addPost(Model model,
                          @RequestParam(name = "title") String title,
                          @RequestParam(name = "sContent") String sContent,
                          @RequestParam(name = "content") String content){

        postRepository.save(new Post(null, title, sContent, content, getUserData(), new Date()));
        return "redirect:/";
    }
    @PostMapping(path = "/addComment/{postId}")
    @PreAuthorize("isAuthenticated()")
    public String addComment(Model model,
                             @RequestParam(name = "content") String content,
                             @PathVariable(name = "postId") Long postId){
        if(content != null) {
            commentRepository.save(new Comment(null, content,
                    postRepository.findById(postId).get(), getUserData(), new Date()));
        }
        return "redirect:/postDetails/" + postId;
    }

    @GetMapping(path = "/deleteComment/{comId}")
    @PreAuthorize("isAuthenticated()")
    public String deleteComment(@PathVariable(name = "comId") Long comId){
        Comment comment = commentRepository.findById(comId).get();
        Long postId = comment.getPost().getId();
        if(comment != null){
            commentRepository.delete(comment);
        }
        return "redirect:/postDetails/" + postId;
    }

    @GetMapping(path = "/postDetails/{postId}")
    public String postDetails(Model model, @PathVariable(name = "postId") Long postId){

        Users user = getUserData();
        if(user != null){
            model.addAttribute("user", user);
        }
        Post post = postRepository.findById(postId).get();
        List<Comment> comments = commentRepository.findAllByPost(post);
        model.addAttribute("post", post);
        model.addAttribute("comments", comments);
        return "postDetails";
    }

    @GetMapping(path = "/editUser/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String editUser(Model model, @PathVariable(name = "id") Long id){

        Users user = userRepository.getOne(id);
        List<Roles> roles = roleRepository.getRolesByIdIsNot(1L);
        model.addAttribute("roles", roles);
        model.addAttribute("user", user);
        return "editUser";
    }

    @GetMapping(path = "/editPost/{postId}")
    @PreAuthorize("hasAnyRole('ROLE_MODERATOR')")
    public String editPost(Model model, @PathVariable(name = "postId") Long postId){

        Post post = postRepository.findById(postId).get();
        model.addAttribute("post", post);
        return "editPost";
    }

    @PostMapping(path = "/savePost/{postId}")
    @PreAuthorize("hasAnyRole('ROLE_MODERATOR')")
    public String savePost(@RequestParam(name = "title") String title,
                           @RequestParam(name = "sContent") String sContent,
                           @RequestParam(name = "content") String content,
                           @PathVariable(name = "postId") Long postId){

        Post post = postRepository.findById(postId).get();
        if(post != null){
            post.setTitle(title);
            post.setShortContent(sContent);
            post.setContent(content);
            postRepository.save(post);
        }
        return "redirect:/postDetails/" + postId;
    }

    @GetMapping(path = "/deletePost/{postId}")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String deleteItem(@PathVariable(name = "postId") Long postId){
        Post post = postRepository.findById(postId).get();
        if(post != null){
            postRepository.delete(post);
        }
        return "redirect:/";
    }

    @GetMapping(path = "/blockUser/{id}")
    @PreAuthorize("hasRole('ROLE_MODERATOR') or hasRole('ROLE_ADMIN')")
    public String blockUser(@PathVariable(name = "id") Long id, SecurityContextHolderAwareRequestWrapper requestWrapper){

        Users user = userRepository.findById(id).get();
        user.setActive(false);
        userRepository.save(user);
        if(requestWrapper.isUserInRole("ROLE_ADMIN")) {
            return "redirect:/manageUsers";
        }
        else {
            return "redirect:/users";
        }
    }

    @GetMapping(path = "/activateUser/{id}")
    @PreAuthorize("hasRole('ROLE_MODERATOR') or hasRole('ROLE_ADMIN')")
    public String activateUser(@PathVariable(name = "id") Long id, SecurityContextHolderAwareRequestWrapper requestWrapper){

        Users user = userRepository.findById(id).get();
        user.setActive(true);
        userRepository.save(user);
        if(requestWrapper.isUserInRole("ROLE_ADMIN")) {
            return "redirect:/manageUsers";
        }
        else {
            return "redirect:/users";
        }
    }

    @GetMapping(path = "/login")
    public String enter(Model model){
        return "login";
    }

    @GetMapping(path = "/register")
    public String register(Model model){
        return "register";
    }

    @GetMapping(path = "/addNewUser")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String addNewUser(Model model){
        List<Roles> roles = roleRepository.getRolesByIdIsNot(1L);
        model.addAttribute("roles", roles);
        return "addNewUser";
    }

    @PostMapping(path = "/createUser")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String createUser(@RequestParam(name = "email") String email,
                          @RequestParam(name = "password") String password,
                          @RequestParam(name = "re_password") String rePassword,
                          @RequestParam(name = "role_id") List<Long> roles_id,
                          @RequestParam(name = "full_name", required = false, defaultValue = "") String fullName){

        String redirect = "redirect:/addNewUser?error";

        Users user = userRepository.findByEmail(email);

        if(user == null){

            if(password.equals(rePassword)){

                Set<Roles> roles = new HashSet<>();
                for(Long r : roles_id){
                    roles.add(roleRepository.getOne(r));
                }

                user = new Users(null, email, password, fullName, roles, true);
                userService.registerUser(user);
                redirect = "redirect:/addNewUser?success";
            }
        }
        return redirect;
    }

    @PostMapping(path = "/updatePassword/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String createUser(@PathVariable(name = "id") Long id,
                             @RequestParam(name = "old_pass") String oldPassword,
                             @RequestParam(name = "password") String password,
                             @RequestParam(name = "re_password") String rePassword){

        String redirect = "redirect:/editUser/{id}?error";

        Users user = userRepository.getOne(id);

        if(user != null){
            if(password.equals(rePassword)){

                if(userService.updatePassword(user, oldPassword, password) != null){
                    redirect = "redirect:/editUser/{id}?success";
                }
            }
        }
        return redirect;
    }
    @PostMapping(path = "/updateRoles/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String createUser(@PathVariable(name = "id") Long id,
                             @RequestParam(name = "role_id") List<Long> roles_id){

        String redirect = "redirect:/editUser/{id}?error";
        Users user = userRepository.getOne(id);

        if(user != null){

                for(Long r : roles_id){
                    user.getRoles().add(roleRepository.getOne(r));
                }
                userRepository.save(user);

                redirect = "redirect:/editUser/{id}?success";
        }
        return redirect;
    }

    @PostMapping(path = "/addUser")
    public String addUser(@RequestParam(name = "email") String email,
                          @RequestParam(name = "password") String password,
                          @RequestParam(name = "re_password") String rePassword,
                          @RequestParam(name = "full_name", required = false, defaultValue = "") String fullName){

        String redirect = "redirect:/register?error";

        Users user = userRepository.findByEmail(email);

        if(user == null){

            if(password.equals(rePassword)){

                Set<Roles> roles = new HashSet<>();
                Roles userRole = roleRepository.getOne(2L);
                roles.add(userRole);

                user = new Users(null, email, password, fullName, roles, true);
                userService.registerUser(user);
                redirect = "redirect:/register?success";
            }
        }
        return redirect;
    }

    @GetMapping(path = "/profile")
    @PreAuthorize("isAuthenticated()")
    public String profile(Model model){

        model.addAttribute("user", getUserData());

        return "profile";
    }

    public Users getUserData(){
        Users userData = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!(authentication instanceof AnonymousAuthenticationToken)){
            User secUser = (User)authentication.getPrincipal();
            userData = userRepository.findByEmail(secUser.getUsername());
        }
        return userData;
    }


}
