package com.sahilkalgutkar.trust.authz.web;

import com.sahilkalgutkar.trust.authz.config.Caller;
import com.sahilkalgutkar.trust.authz.config.CallerContext;
import com.sahilkalgutkar.trust.authz.engine.CheckEngine;
import com.sahilkalgutkar.trust.authz.engine.CheckResult;
import com.sahilkalgutkar.trust.authz.engine.ExpandEngine;
import com.sahilkalgutkar.trust.authz.engine.NamespaceCatalog;
import com.sahilkalgutkar.trust.authz.engine.TupleChange;
import com.sahilkalgutkar.trust.authz.engine.TupleWriter;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Zookie;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * The authorization API.
 *
 * <p>Two scopes separate the two very different privileges here: {@code authz.check} asks questions
 * and {@code authz.write} changes answers. An application server needs the first on every request
 * and the second almost never, so they are not the same permission.
 */
@RestController
public class AuthzController {

    private static final String SCOPE_CHECK = "authz.check";
    private static final String SCOPE_WRITE = "authz.write";

    private final CheckEngine checkEngine;
    private final ExpandEngine expandEngine;
    private final TupleWriter tupleWriter;
    private final NamespaceCatalog namespaceCatalog;

    public AuthzController(CheckEngine checkEngine, ExpandEngine expandEngine, TupleWriter tupleWriter,
                           NamespaceCatalog namespaceCatalog) {
        this.checkEngine = checkEngine;
        this.expandEngine = expandEngine;
        this.tupleWriter = tupleWriter;
        this.namespaceCatalog = namespaceCatalog;
    }

    @PostMapping("/t/{tenant}/v1/check")
    public AuthzApi.CheckResponse check(@PathVariable("tenant") String tenant,
                                        @Valid @RequestBody AuthzApi.CheckRequest request) {
        Caller caller = CallerContext.requireScope(SCOPE_CHECK);
        CheckResult result = checkEngine.check(caller.tenantId(), request.namespace(), request.object(),
                request.relation(), request.subjectRef(), Zookie.decode(request.zookie()));

        return new AuthzApi.CheckResponse(result.allowed(), Zookie.of(result.revision()).encode(),
                result.fromCache(), result.tuplesRead(), result.maxDepthReached());
    }

    @PostMapping("/t/{tenant}/v1/expand")
    public AuthzApi.ExpandResponse expand(@PathVariable("tenant") String tenant,
                                          @Valid @RequestBody AuthzApi.ExpandRequest request) {
        Caller caller = CallerContext.requireScope(SCOPE_CHECK);
        return new AuthzApi.ExpandResponse(expandEngine.expand(caller.tenantId(), request.namespace(),
                request.object(), request.relation()));
    }

    @PostMapping("/t/{tenant}/v1/tuples")
    public AuthzApi.WriteResponse write(@PathVariable("tenant") String tenant,
                                        @RequestBody AuthzApi.WriteRequest request) {
        Caller caller = CallerContext.requireScope(SCOPE_WRITE);
        List<TupleChange> changes = request.toChanges();
        Zookie zookie = tupleWriter.apply(caller.tenantId(), "user:" + caller.subject(), changes);
        return new AuthzApi.WriteResponse(zookie.encode(), changes.size());
    }

    @PostMapping("/t/{tenant}/v1/namespaces")
    @ResponseStatus(HttpStatus.CREATED)
    public AuthzApi.NamespaceResponse writeNamespace(@PathVariable("tenant") String tenant,
                                                     @Valid @RequestBody AuthzApi.NamespaceRequest request) {
        Caller caller = CallerContext.requireScope(SCOPE_WRITE);
        NamespaceConfig saved = namespaceCatalog.save(caller.tenantId(),
                new NamespaceConfig(request.name(), request.relations()));
        return new AuthzApi.NamespaceResponse(saved.name(), saved.relations());
    }

    @GetMapping("/t/{tenant}/v1/namespaces/{name}")
    public AuthzApi.NamespaceResponse readNamespace(@PathVariable("tenant") String tenant,
                                                    @PathVariable("name") String name) {
        Caller caller = CallerContext.requireScope(SCOPE_CHECK);
        NamespaceConfig config = namespaceCatalog.require(caller.tenantId(), name);
        return new AuthzApi.NamespaceResponse(config.name(), config.relations());
    }

    @GetMapping("/t/{tenant}/v1/namespaces")
    public List<String> listNamespaces(@PathVariable("tenant") String tenant) {
        Caller caller = CallerContext.requireScope(SCOPE_CHECK);
        return namespaceCatalog.names(caller.tenantId());
    }
}
