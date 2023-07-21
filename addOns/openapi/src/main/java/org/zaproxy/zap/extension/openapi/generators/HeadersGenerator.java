/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.openapi.generators;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;

public class HeadersGenerator {

    private static final String ACCEPT = "accept";
    private static final String HEADER = "header";
    private static final String COOKIE = "cookie";

    private static final char COOKIE_NAME_VALUE_SEPARATOR = '=';
    private static final String COOKIE_SEPARATOR = "; ";

    private DataGenerator dataGenerator;

    public HeadersGenerator(DataGenerator dataGenerator) {
        this.dataGenerator = dataGenerator;
    }

    public List<HttpHeaderField> generate(OperationModel operationModel, String requestBody) {
        List<HttpHeaderField> headerList = new LinkedList<>();
        generateAcceptHeaders(operationModel.getOperation(), headerList);
        generateContentTypeHeaders(operationModel.getOperation(), headerList, requestBody);
        generateCustomHeader(operationModel.getOperation(), headerList);
        return headerList;
    }

    void generateCustomHeader(Operation operation, List<HttpHeaderField> headers) {
        if (operation.getParameters() != null) {
            List<Parameter> cookies = null;
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null) {
                    continue;
                }
                if (HEADER.equals(parameter.getIn())) {
                    String name = parameter.getName();
                    String value = dataGenerator.generate(name, parameter);
                    HttpHeaderField header = new HttpHeaderField(name, value);
                    headers.add(header);
                } else if (COOKIE.equals(parameter.getIn())) {
                    if (cookies == null) {
                        cookies = new ArrayList<>();
                    }
                    cookies.add(parameter);
                }
            }

            if (cookies != null) {
                headers.add(generateCookieHeader(cookies));
            }
        }
    }

    HttpHeaderField generateCookieHeader(List<Parameter> cookies) {
        StringBuilder strBuilder = new StringBuilder(cookies.size() * 15);
        cookies.forEach(
                cookie -> {
                    if (strBuilder.length() != 0) {
                        strBuilder.append(COOKIE_SEPARATOR);
                    }
                    strBuilder.append(cookie.getName()).append(COOKIE_NAME_VALUE_SEPARATOR);
                    strBuilder.append(dataGenerator.generate(cookie.getName(), cookie));
                });
        return new HttpHeaderField(HttpHeader.COOKIE, strBuilder.toString());
    }

    void generateContentTypeHeaders(
            Operation operation, List<HttpHeaderField> headers, String requestBody) {
        if (operation.getRequestBody() == null || operation.getRequestBody().getContent() == null) {
            return;
        }

        // Note: the order in which the content types are evaluated should match the order in
        // RequestModelConverter.
        Set<String> contentTypes = operation.getRequestBody().getContent().keySet();
        String contentType =
                getPartialMatch(contentTypes, "json", "x-www-form-urlencoded", "octet-stream");
        if (contentType != null) {
            headers.add(new HttpHeaderField(HttpHeader.CONTENT_TYPE, contentType));
            return;
        }

        contentType = getPartialMatch(contentTypes, "multipart");
        if (contentType != null) {
            if (requestBody.length() > 0) {
                contentType += "; boundary=" + requestBody.substring(2, 38);
            }
            headers.add(new HttpHeaderField(HttpHeader.CONTENT_TYPE, contentType));
        }
    }

    private static String getPartialMatch(Set<String> values, String... wantedMatches) {
        for (String wantedMatch : wantedMatches) {
            Optional<String> match =
                    values.stream()
                            .filter(e -> StringUtils.containsIgnoreCase(e, wantedMatch))
                            .findFirst();
            if (match.isPresent()) {
                return match.get();
            }
        }
        return null;
    }

    void generateAcceptHeaders(Operation operation, List<HttpHeaderField> headers) {

        Set<String> contentSet = new LinkedHashSet<>();
        if (operation.getResponses() != null) {
            operation.getResponses().values().stream()
                    .map(
                            response -> {
                                if (response.getContent() == null) {
                                    return Collections.<String>emptySet();
                                }
                                return response.getContent().keySet();
                            })
                    .forEach(contentSet::addAll);
        }
        StringBuilder sb = new StringBuilder();
        for (String type : contentSet) {
            // Claim we accept everything
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(type);
        }

        String headerValue = sb.toString();
        if (headerValue.isEmpty()) {
            headerValue = "*/*";
        }
        headers.add(new HttpHeaderField(ACCEPT, headerValue));
    }
}
