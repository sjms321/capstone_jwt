package me.silvernine.tutorial.repository;

import me.silvernine.tutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    //쿼리가 수행될때 lazy(지연조회)조회가 아니고 eager(즉시로딩)조회로 authorities정보를 같이 가져오게된다.
    @EntityGraph(attributePaths = "authorities")
    //username을 기준으로 user정보를 가져올때 권한 정보도 같이 가져오게된다.
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}