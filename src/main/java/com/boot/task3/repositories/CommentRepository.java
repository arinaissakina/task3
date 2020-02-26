package com.boot.task3.repositories;

import com.boot.task3.entities.Comment;
import com.boot.task3.entities.Post;
import com.boot.task3.entities.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CommentRepository extends JpaRepository<Comment, Long> {
    List<Comment> findAll();
    Optional<Comment> findById(Long id);
    List<Comment> findAllByPost(Post post);
}
