--
-- PostgreSQL database dump
--

-- Dumped from database version 16.2
-- Dumped by pg_dump version 16.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: infisical
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO infisical;

--
-- Name: on_update_timestamp(); Type: FUNCTION; Schema: public; Owner: infisical
--

CREATE FUNCTION public.on_update_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN NEW."updatedAt" = NOW();
RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_timestamp() OWNER TO infisical;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_approval_policies; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.access_approval_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    approvals integer DEFAULT 1 NOT NULL,
    "secretPath" character varying(255),
    "envId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "enforcementLevel" character varying(10) DEFAULT 'hard'::character varying NOT NULL
);


ALTER TABLE public.access_approval_policies OWNER TO infisical;

--
-- Name: access_approval_policies_approvers; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.access_approval_policies_approvers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "policyId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "approverUserId" uuid,
    "approverGroupId" uuid
);


ALTER TABLE public.access_approval_policies_approvers OWNER TO infisical;

--
-- Name: access_approval_requests; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.access_approval_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "policyId" uuid NOT NULL,
    "privilegeId" uuid,
    "requestedBy" uuid,
    "isTemporary" boolean NOT NULL,
    "temporaryRange" character varying(255),
    permissions jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "requestedByUserId" uuid NOT NULL
);


ALTER TABLE public.access_approval_requests OWNER TO infisical;

--
-- Name: access_approval_requests_reviewers; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.access_approval_requests_reviewers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    member uuid,
    status character varying(255) NOT NULL,
    "requestId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "reviewerUserId" uuid NOT NULL
);


ALTER TABLE public.access_approval_requests_reviewers OWNER TO infisical;

--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.api_keys (
    id character varying(36) DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    "lastUsed" timestamp with time zone,
    "expiresAt" timestamp with time zone,
    "secretHash" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid NOT NULL
);


ALTER TABLE public.api_keys OWNER TO infisical;

--
-- Name: audit_log_streams; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.audit_log_streams (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    url character varying(255) NOT NULL,
    "encryptedHeadersCiphertext" text,
    "encryptedHeadersIV" text,
    "encryptedHeadersTag" text,
    "encryptedHeadersAlgorithm" character varying(255),
    "encryptedHeadersKeyEncoding" character varying(255),
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.audit_log_streams OWNER TO infisical;

--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.audit_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor character varying(255) NOT NULL,
    "actorMetadata" jsonb NOT NULL,
    "ipAddress" character varying(255),
    "eventType" character varying(255) NOT NULL,
    "eventMetadata" jsonb,
    "userAgent" character varying(255),
    "userAgentType" character varying(255),
    "expiresAt" timestamp with time zone,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "orgId" uuid,
    "projectId" character varying(255),
    "projectName" character varying(255)
);


ALTER TABLE public.audit_logs OWNER TO infisical;

--
-- Name: auth_token_sessions; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.auth_token_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ip character varying(255) NOT NULL,
    "userAgent" character varying(255),
    "refreshVersion" integer DEFAULT 1 NOT NULL,
    "accessVersion" integer DEFAULT 1 NOT NULL,
    "lastUsed" timestamp with time zone NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid NOT NULL
);


ALTER TABLE public.auth_token_sessions OWNER TO infisical;

--
-- Name: auth_tokens; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.auth_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    type character varying(255) NOT NULL,
    "phoneNumber" character varying(255),
    "tokenHash" character varying(255) NOT NULL,
    "triesLeft" integer,
    "expiresAt" timestamp with time zone NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid,
    "orgId" uuid
);


ALTER TABLE public.auth_tokens OWNER TO infisical;

--
-- Name: backup_private_key; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.backup_private_key (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "encryptedPrivateKey" text NOT NULL,
    iv text NOT NULL,
    tag text NOT NULL,
    algorithm character varying(255) NOT NULL,
    "keyEncoding" character varying(255) NOT NULL,
    salt text NOT NULL,
    verifier text NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid NOT NULL
);


ALTER TABLE public.backup_private_key OWNER TO infisical;

--
-- Name: certificate_authorities; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificate_authorities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "parentCaId" uuid,
    "projectId" character varying(255) NOT NULL,
    type character varying(255) NOT NULL,
    status character varying(255) NOT NULL,
    "friendlyName" character varying(255) NOT NULL,
    organization character varying(255) NOT NULL,
    ou character varying(255) NOT NULL,
    country character varying(255) NOT NULL,
    province character varying(255) NOT NULL,
    locality character varying(255) NOT NULL,
    "commonName" character varying(255) NOT NULL,
    dn character varying(255) NOT NULL,
    "serialNumber" character varying(255),
    "maxPathLength" integer,
    "keyAlgorithm" character varying(255) NOT NULL,
    "notBefore" timestamp with time zone,
    "notAfter" timestamp with time zone,
    "activeCaCertId" uuid,
    "requireTemplateForIssuance" boolean DEFAULT false NOT NULL
);


ALTER TABLE public.certificate_authorities OWNER TO infisical;

--
-- Name: certificate_authority_certs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificate_authority_certs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "caId" uuid NOT NULL,
    "encryptedCertificate" bytea NOT NULL,
    "encryptedCertificateChain" bytea NOT NULL,
    version integer NOT NULL,
    "caSecretId" uuid NOT NULL
);


ALTER TABLE public.certificate_authority_certs OWNER TO infisical;

--
-- Name: certificate_authority_crl; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificate_authority_crl (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "caId" uuid NOT NULL,
    "encryptedCrl" bytea NOT NULL,
    "caSecretId" uuid NOT NULL
);


ALTER TABLE public.certificate_authority_crl OWNER TO infisical;

--
-- Name: certificate_authority_secret; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificate_authority_secret (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "caId" uuid NOT NULL,
    "encryptedPrivateKey" bytea NOT NULL
);


ALTER TABLE public.certificate_authority_secret OWNER TO infisical;

--
-- Name: certificate_bodies; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificate_bodies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "certId" uuid NOT NULL,
    "encryptedCertificate" bytea NOT NULL
);


ALTER TABLE public.certificate_bodies OWNER TO infisical;

--
-- Name: certificate_template_est_configs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificate_template_est_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "certificateTemplateId" uuid NOT NULL,
    "encryptedCaChain" bytea NOT NULL,
    "hashedPassphrase" character varying(255) NOT NULL,
    "isEnabled" boolean NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.certificate_template_est_configs OWNER TO infisical;

--
-- Name: certificate_templates; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificate_templates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "caId" uuid NOT NULL,
    "pkiCollectionId" uuid,
    name character varying(255) NOT NULL,
    "commonName" character varying(255) NOT NULL,
    "subjectAlternativeName" character varying(255) NOT NULL,
    ttl character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "keyUsages" text[],
    "extendedKeyUsages" text[]
);


ALTER TABLE public.certificate_templates OWNER TO infisical;

--
-- Name: certificates; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "caId" uuid NOT NULL,
    status character varying(255) NOT NULL,
    "serialNumber" character varying(255) NOT NULL,
    "friendlyName" character varying(255) NOT NULL,
    "commonName" character varying(255) NOT NULL,
    "notBefore" timestamp with time zone NOT NULL,
    "notAfter" timestamp with time zone NOT NULL,
    "revokedAt" timestamp with time zone,
    "revocationReason" integer,
    "altNames" character varying(255) DEFAULT ''::character varying,
    "caCertId" uuid NOT NULL,
    "certificateTemplateId" uuid,
    "keyUsages" text[],
    "extendedKeyUsages" text[]
);


ALTER TABLE public.certificates OWNER TO infisical;

--
-- Name: dynamic_secret_leases; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.dynamic_secret_leases (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer NOT NULL,
    "externalEntityId" character varying(255) NOT NULL,
    "expireAt" timestamp with time zone NOT NULL,
    status character varying(255),
    "statusDetails" character varying(255),
    "dynamicSecretId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.dynamic_secret_leases OWNER TO infisical;

--
-- Name: dynamic_secrets; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.dynamic_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    version integer NOT NULL,
    type character varying(255) NOT NULL,
    "defaultTTL" character varying(255) NOT NULL,
    "maxTTL" character varying(255),
    "inputIV" character varying(255) NOT NULL,
    "inputCiphertext" text NOT NULL,
    "inputTag" character varying(255) NOT NULL,
    algorithm character varying(255) DEFAULT 'aes-256-gcm'::character varying NOT NULL,
    "keyEncoding" character varying(255) DEFAULT 'utf8'::character varying NOT NULL,
    "folderId" uuid NOT NULL,
    status character varying(255),
    "statusDetails" character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.dynamic_secrets OWNER TO infisical;

--
-- Name: external_group_org_role_mappings; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.external_group_org_role_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "groupName" character varying(255) NOT NULL,
    role character varying(255) NOT NULL,
    "roleId" uuid,
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.external_group_org_role_mappings OWNER TO infisical;

--
-- Name: external_kms; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.external_kms (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider character varying(255) NOT NULL,
    "encryptedProviderInputs" bytea NOT NULL,
    status character varying(255),
    "statusDetails" character varying(255),
    "kmsKeyId" uuid NOT NULL
);


ALTER TABLE public.external_kms OWNER TO infisical;

--
-- Name: git_app_install_sessions; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.git_app_install_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "sessionId" character varying(255) NOT NULL,
    "userId" uuid,
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.git_app_install_sessions OWNER TO infisical;

--
-- Name: git_app_org; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.git_app_org (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "installationId" character varying(255) NOT NULL,
    "userId" uuid NOT NULL,
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.git_app_org OWNER TO infisical;

--
-- Name: group_project_membership_roles; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.group_project_membership_roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role character varying(255) NOT NULL,
    "projectMembershipId" uuid NOT NULL,
    "customRoleId" uuid,
    "isTemporary" boolean DEFAULT false NOT NULL,
    "temporaryMode" character varying(255),
    "temporaryRange" character varying(255),
    "temporaryAccessStartTime" timestamp with time zone,
    "temporaryAccessEndTime" timestamp with time zone,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.group_project_membership_roles OWNER TO infisical;

--
-- Name: group_project_memberships; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.group_project_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "projectId" character varying(255) NOT NULL,
    "groupId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.group_project_memberships OWNER TO infisical;

--
-- Name: groups; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "orgId" uuid NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(255) NOT NULL,
    role character varying(255) NOT NULL,
    "roleId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.groups OWNER TO infisical;

--
-- Name: identities; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    "authMethod" character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.identities OWNER TO infisical;

--
-- Name: identity_access_tokens; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_access_tokens (
    id character varying(36) DEFAULT gen_random_uuid() NOT NULL,
    "accessTokenTTL" bigint DEFAULT '2592000'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '2592000'::bigint NOT NULL,
    "accessTokenNumUses" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenLastUsedAt" timestamp with time zone,
    "accessTokenLastRenewedAt" timestamp with time zone,
    "isAccessTokenRevoked" boolean DEFAULT false NOT NULL,
    "identityUAClientSecretId" character varying(255),
    "identityId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    name character varying(255),
    "authMethod" character varying(255) NOT NULL
);


ALTER TABLE public.identity_access_tokens OWNER TO infisical;

--
-- Name: identity_aws_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_aws_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "accessTokenTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenTrustedIps" jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityId" uuid NOT NULL,
    type character varying(255) NOT NULL,
    "stsEndpoint" character varying(255) NOT NULL,
    "allowedPrincipalArns" character varying(255) NOT NULL,
    "allowedAccountIds" character varying(255) NOT NULL
);


ALTER TABLE public.identity_aws_auths OWNER TO infisical;

--
-- Name: identity_azure_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_azure_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "accessTokenTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenTrustedIps" jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityId" uuid NOT NULL,
    "tenantId" character varying(255) NOT NULL,
    resource character varying(255) NOT NULL,
    "allowedServicePrincipalIds" character varying(255) NOT NULL
);


ALTER TABLE public.identity_azure_auths OWNER TO infisical;

--
-- Name: identity_gcp_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_gcp_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "accessTokenTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenTrustedIps" jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityId" uuid NOT NULL,
    type character varying(255) NOT NULL,
    "allowedServiceAccounts" character varying(255) NOT NULL,
    "allowedProjects" character varying(255) NOT NULL,
    "allowedZones" character varying(255) NOT NULL
);


ALTER TABLE public.identity_gcp_auths OWNER TO infisical;

--
-- Name: identity_kubernetes_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_kubernetes_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "accessTokenTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenTrustedIps" jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityId" uuid NOT NULL,
    "kubernetesHost" character varying(255) NOT NULL,
    "encryptedCaCert" text NOT NULL,
    "caCertIV" character varying(255) NOT NULL,
    "caCertTag" character varying(255) NOT NULL,
    "encryptedTokenReviewerJwt" text NOT NULL,
    "tokenReviewerJwtIV" character varying(255) NOT NULL,
    "tokenReviewerJwtTag" character varying(255) NOT NULL,
    "allowedNamespaces" character varying(255) NOT NULL,
    "allowedNames" character varying(255) NOT NULL,
    "allowedAudience" character varying(255) NOT NULL
);


ALTER TABLE public.identity_kubernetes_auths OWNER TO infisical;

--
-- Name: identity_metadata; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_metadata (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key character varying(255) NOT NULL,
    value character varying(1020),
    "orgId" uuid NOT NULL,
    "userId" uuid,
    "identityId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.identity_metadata OWNER TO infisical;

--
-- Name: identity_oidc_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_oidc_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "accessTokenTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenTrustedIps" jsonb NOT NULL,
    "identityId" uuid NOT NULL,
    "oidcDiscoveryUrl" character varying(255) NOT NULL,
    "encryptedCaCert" text NOT NULL,
    "caCertIV" character varying(255) NOT NULL,
    "caCertTag" character varying(255) NOT NULL,
    "boundIssuer" character varying(255) NOT NULL,
    "boundAudiences" character varying(255) NOT NULL,
    "boundClaims" jsonb NOT NULL,
    "boundSubject" character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.identity_oidc_auths OWNER TO infisical;

--
-- Name: identity_org_memberships; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_org_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role character varying(255) NOT NULL,
    "roleId" uuid,
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityId" uuid NOT NULL
);


ALTER TABLE public.identity_org_memberships OWNER TO infisical;

--
-- Name: identity_project_additional_privilege; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_project_additional_privilege (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug character varying(60) NOT NULL,
    "projectMembershipId" uuid NOT NULL,
    "isTemporary" boolean DEFAULT false NOT NULL,
    "temporaryMode" character varying(255),
    "temporaryRange" character varying(255),
    "temporaryAccessStartTime" timestamp with time zone,
    "temporaryAccessEndTime" timestamp with time zone,
    permissions jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.identity_project_additional_privilege OWNER TO infisical;

--
-- Name: identity_project_membership_role; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_project_membership_role (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role character varying(255) NOT NULL,
    "projectMembershipId" uuid NOT NULL,
    "customRoleId" uuid,
    "isTemporary" boolean DEFAULT false NOT NULL,
    "temporaryMode" character varying(255),
    "temporaryRange" character varying(255),
    "temporaryAccessStartTime" timestamp with time zone,
    "temporaryAccessEndTime" timestamp with time zone,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.identity_project_membership_role OWNER TO infisical;

--
-- Name: identity_project_memberships; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_project_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "projectId" character varying(255) NOT NULL,
    "identityId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.identity_project_memberships OWNER TO infisical;

--
-- Name: identity_token_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_token_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "accessTokenTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "accessTokenTrustedIps" jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityId" uuid NOT NULL
);


ALTER TABLE public.identity_token_auths OWNER TO infisical;

--
-- Name: identity_ua_client_secrets; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_ua_client_secrets (
    id character varying(36) DEFAULT gen_random_uuid() NOT NULL,
    description character varying(255) NOT NULL,
    "clientSecretPrefix" character varying(255) NOT NULL,
    "clientSecretHash" character varying(255) NOT NULL,
    "clientSecretLastUsedAt" timestamp with time zone,
    "clientSecretNumUses" bigint DEFAULT '0'::bigint NOT NULL,
    "clientSecretNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "clientSecretTTL" bigint DEFAULT '0'::bigint NOT NULL,
    "isClientSecretRevoked" boolean DEFAULT false NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityUAId" uuid NOT NULL
);


ALTER TABLE public.identity_ua_client_secrets OWNER TO infisical;

--
-- Name: identity_universal_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.identity_universal_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "clientId" character varying(255) NOT NULL,
    "accessTokenTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenMaxTTL" bigint DEFAULT '7200'::bigint NOT NULL,
    "accessTokenNumUsesLimit" bigint DEFAULT '0'::bigint NOT NULL,
    "clientSecretTrustedIps" jsonb NOT NULL,
    "accessTokenTrustedIps" jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "identityId" uuid NOT NULL
);


ALTER TABLE public.identity_universal_auths OWNER TO infisical;

--
-- Name: incident_contacts; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.incident_contacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "orgId" uuid NOT NULL
);


ALTER TABLE public.incident_contacts OWNER TO infisical;

--
-- Name: infisical_migrations; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.infisical_migrations (
    id integer NOT NULL,
    name character varying(255),
    batch integer,
    migration_time timestamp with time zone
);


ALTER TABLE public.infisical_migrations OWNER TO infisical;

--
-- Name: infisical_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: infisical
--

CREATE SEQUENCE public.infisical_migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.infisical_migrations_id_seq OWNER TO infisical;

--
-- Name: infisical_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: infisical
--

ALTER SEQUENCE public.infisical_migrations_id_seq OWNED BY public.infisical_migrations.id;


--
-- Name: infisical_migrations_lock; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.infisical_migrations_lock (
    index integer NOT NULL,
    is_locked integer
);


ALTER TABLE public.infisical_migrations_lock OWNER TO infisical;

--
-- Name: infisical_migrations_lock_index_seq; Type: SEQUENCE; Schema: public; Owner: infisical
--

CREATE SEQUENCE public.infisical_migrations_lock_index_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.infisical_migrations_lock_index_seq OWNER TO infisical;

--
-- Name: infisical_migrations_lock_index_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: infisical
--

ALTER SEQUENCE public.infisical_migrations_lock_index_seq OWNED BY public.infisical_migrations_lock.index;


--
-- Name: integration_auths; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.integration_auths (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration character varying(255) NOT NULL,
    "teamId" character varying(255),
    url character varying(255),
    namespace character varying(255),
    "accountId" character varying(255),
    "refreshCiphertext" text,
    "refreshIV" character varying(255),
    "refreshTag" character varying(255),
    "accessIdCiphertext" character varying(255),
    "accessIdIV" character varying(255),
    "accessIdTag" character varying(255),
    "accessCiphertext" text,
    "accessIV" character varying(255),
    "accessTag" character varying(255),
    "accessExpiresAt" timestamp with time zone,
    metadata jsonb,
    algorithm character varying(255) NOT NULL,
    "keyEncoding" character varying(255) NOT NULL,
    "projectId" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "awsAssumeIamRoleArnCipherText" text,
    "awsAssumeIamRoleArnIV" text,
    "awsAssumeIamRoleArnTag" text,
    "encryptedAccess" bytea,
    "encryptedAccessId" bytea,
    "encryptedRefresh" bytea,
    "encryptedAwsAssumeIamRoleArn" bytea
);


ALTER TABLE public.integration_auths OWNER TO infisical;

--
-- Name: integrations; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "isActive" boolean NOT NULL,
    url character varying(255),
    app character varying(255),
    "appId" character varying(255),
    "targetEnvironment" character varying(255),
    "targetEnvironmentId" character varying(255),
    "targetService" character varying(255),
    "targetServiceId" character varying(255),
    owner character varying(255),
    path character varying(255),
    region character varying(255),
    scope character varying(255),
    integration character varying(255) NOT NULL,
    metadata jsonb,
    "integrationAuthId" uuid NOT NULL,
    "envId" uuid NOT NULL,
    "secretPath" character varying(255) DEFAULT '/'::character varying NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "lastUsed" timestamp with time zone,
    "isSynced" boolean,
    "syncMessage" text,
    "lastSyncJobId" character varying(255)
);


ALTER TABLE public.integrations OWNER TO infisical;

--
-- Name: internal_kms; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.internal_kms (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "encryptedKey" bytea NOT NULL,
    "encryptionAlgorithm" character varying(255) NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    "kmsKeyId" uuid NOT NULL
);


ALTER TABLE public.internal_kms OWNER TO infisical;

--
-- Name: internal_kms_key_version; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.internal_kms_key_version (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "encryptedKey" bytea NOT NULL,
    version integer NOT NULL,
    "internalKmsId" uuid NOT NULL
);


ALTER TABLE public.internal_kms_key_version OWNER TO infisical;

--
-- Name: kms_keys; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.kms_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    description character varying(255),
    "isDisabled" boolean DEFAULT false,
    "isReserved" boolean DEFAULT true,
    "orgId" uuid NOT NULL,
    name character varying(32) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "projectId" character varying(255),
    slug character varying(32)
);


ALTER TABLE public.kms_keys OWNER TO infisical;

--
-- Name: kms_root_config; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.kms_root_config (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "encryptedRootKey" bytea NOT NULL
);


ALTER TABLE public.kms_root_config OWNER TO infisical;

--
-- Name: ldap_configs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.ldap_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "orgId" uuid NOT NULL,
    "isActive" boolean NOT NULL,
    url character varying(255) NOT NULL,
    "encryptedBindDN" character varying(255) NOT NULL,
    "bindDNIV" character varying(255) NOT NULL,
    "bindDNTag" character varying(255) NOT NULL,
    "encryptedBindPass" character varying(255) NOT NULL,
    "bindPassIV" character varying(255) NOT NULL,
    "bindPassTag" character varying(255) NOT NULL,
    "searchBase" character varying(255) NOT NULL,
    "encryptedCACert" text NOT NULL,
    "caCertIV" character varying(255) NOT NULL,
    "caCertTag" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "groupSearchBase" character varying(255) DEFAULT ''::character varying NOT NULL,
    "groupSearchFilter" character varying(255) DEFAULT ''::character varying NOT NULL,
    "searchFilter" character varying(255) DEFAULT ''::character varying NOT NULL,
    "uniqueUserAttribute" character varying(255) DEFAULT ''::character varying NOT NULL
);


ALTER TABLE public.ldap_configs OWNER TO infisical;

--
-- Name: ldap_group_maps; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.ldap_group_maps (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "ldapConfigId" uuid NOT NULL,
    "ldapGroupCN" character varying(255) NOT NULL,
    "groupId" uuid NOT NULL
);


ALTER TABLE public.ldap_group_maps OWNER TO infisical;

--
-- Name: oidc_configs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.oidc_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "discoveryURL" character varying(255),
    issuer character varying(255),
    "authorizationEndpoint" character varying(255),
    "jwksUri" character varying(255),
    "tokenEndpoint" character varying(255),
    "userinfoEndpoint" character varying(255),
    "encryptedClientId" text NOT NULL,
    "configurationType" character varying(255) NOT NULL,
    "clientIdIV" character varying(255) NOT NULL,
    "clientIdTag" character varying(255) NOT NULL,
    "encryptedClientSecret" text NOT NULL,
    "clientSecretIV" character varying(255) NOT NULL,
    "clientSecretTag" character varying(255) NOT NULL,
    "allowedEmailDomains" character varying(255),
    "isActive" boolean NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "orgId" uuid NOT NULL,
    "lastUsed" timestamp with time zone
);


ALTER TABLE public.oidc_configs OWNER TO infisical;

--
-- Name: org_bots; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.org_bots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    "publicKey" text NOT NULL,
    "encryptedSymmetricKey" text NOT NULL,
    "symmetricKeyIV" text NOT NULL,
    "symmetricKeyTag" text NOT NULL,
    "symmetricKeyAlgorithm" character varying(255) NOT NULL,
    "symmetricKeyKeyEncoding" character varying(255) NOT NULL,
    "encryptedPrivateKey" text NOT NULL,
    "privateKeyIV" text NOT NULL,
    "privateKeyTag" text NOT NULL,
    "privateKeyAlgorithm" character varying(255) NOT NULL,
    "privateKeyKeyEncoding" character varying(255) NOT NULL,
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.org_bots OWNER TO infisical;

--
-- Name: org_memberships; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.org_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role character varying(255) NOT NULL,
    status character varying(255) DEFAULT 'invited'::character varying NOT NULL,
    "inviteEmail" character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid,
    "orgId" uuid NOT NULL,
    "roleId" uuid,
    "projectFavorites" text[],
    "isActive" boolean DEFAULT true NOT NULL
);


ALTER TABLE public.org_memberships OWNER TO infisical;

--
-- Name: org_roles; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.org_roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    slug character varying(255) NOT NULL,
    permissions jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "orgId" uuid NOT NULL
);


ALTER TABLE public.org_roles OWNER TO infisical;

--
-- Name: organizations; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    "customerId" character varying(255),
    slug character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "authEnforced" boolean DEFAULT false,
    "scimEnabled" boolean DEFAULT false,
    "kmsDefaultKeyId" uuid,
    "kmsEncryptedDataKey" bytea,
    "defaultMembershipRole" character varying(255) DEFAULT 'member'::character varying NOT NULL,
    "enforceMfa" boolean DEFAULT false NOT NULL
);


ALTER TABLE public.organizations OWNER TO infisical;

--
-- Name: pki_alerts; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.pki_alerts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "projectId" character varying(255) NOT NULL,
    "pkiCollectionId" uuid NOT NULL,
    name character varying(255) NOT NULL,
    "alertBeforeDays" integer NOT NULL,
    "recipientEmails" character varying(255) NOT NULL
);


ALTER TABLE public.pki_alerts OWNER TO infisical;

--
-- Name: pki_collection_items; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.pki_collection_items (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "pkiCollectionId" uuid NOT NULL,
    "caId" uuid,
    "certId" uuid
);


ALTER TABLE public.pki_collection_items OWNER TO infisical;

--
-- Name: pki_collections; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.pki_collections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "projectId" character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255) NOT NULL
);


ALTER TABLE public.pki_collections OWNER TO infisical;

--
-- Name: project_bots; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_bots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    "isActive" boolean DEFAULT false NOT NULL,
    "encryptedPrivateKey" text NOT NULL,
    "publicKey" text NOT NULL,
    iv text NOT NULL,
    tag text NOT NULL,
    algorithm character varying(255) NOT NULL,
    "keyEncoding" character varying(255) NOT NULL,
    "encryptedProjectKey" text,
    "encryptedProjectKeyNonce" text,
    "projectId" character varying(255) NOT NULL,
    "senderId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.project_bots OWNER TO infisical;

--
-- Name: project_environments; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_environments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(255) NOT NULL,
    "position" integer NOT NULL,
    "projectId" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.project_environments OWNER TO infisical;

--
-- Name: project_keys; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "encryptedKey" text NOT NULL,
    nonce text NOT NULL,
    "receiverId" uuid NOT NULL,
    "senderId" uuid,
    "projectId" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.project_keys OWNER TO infisical;

--
-- Name: project_memberships; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid NOT NULL,
    "projectId" character varying(255) NOT NULL
);


ALTER TABLE public.project_memberships OWNER TO infisical;

--
-- Name: project_roles; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    slug character varying(255) NOT NULL,
    permissions jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "projectId" character varying(255) NOT NULL,
    version integer DEFAULT 1 NOT NULL
);


ALTER TABLE public.project_roles OWNER TO infisical;

--
-- Name: project_slack_configs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_slack_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "projectId" character varying(255) NOT NULL,
    "slackIntegrationId" uuid NOT NULL,
    "isAccessRequestNotificationEnabled" boolean DEFAULT false NOT NULL,
    "accessRequestChannels" character varying(255) DEFAULT ''::character varying NOT NULL,
    "isSecretRequestNotificationEnabled" boolean DEFAULT false NOT NULL,
    "secretRequestChannels" character varying(255) DEFAULT ''::character varying NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.project_slack_configs OWNER TO infisical;

--
-- Name: project_user_additional_privilege; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_user_additional_privilege (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug character varying(60) NOT NULL,
    "projectMembershipId" uuid,
    "isTemporary" boolean DEFAULT false NOT NULL,
    "temporaryMode" character varying(255),
    "temporaryRange" character varying(255),
    "temporaryAccessStartTime" timestamp with time zone,
    "temporaryAccessEndTime" timestamp with time zone,
    permissions jsonb NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid NOT NULL,
    "projectId" character varying(255) NOT NULL
);


ALTER TABLE public.project_user_additional_privilege OWNER TO infisical;

--
-- Name: project_user_membership_roles; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.project_user_membership_roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role character varying(255) NOT NULL,
    "projectMembershipId" uuid NOT NULL,
    "customRoleId" uuid,
    "isTemporary" boolean DEFAULT false NOT NULL,
    "temporaryMode" character varying(255),
    "temporaryRange" character varying(255),
    "temporaryAccessStartTime" timestamp with time zone,
    "temporaryAccessEndTime" timestamp with time zone,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.project_user_membership_roles OWNER TO infisical;

--
-- Name: projects; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.projects (
    id character varying(36) DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(255) NOT NULL,
    "autoCapitalization" boolean DEFAULT true,
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    "upgradeStatus" character varying(255),
    "pitVersionLimit" integer DEFAULT 10 NOT NULL,
    "kmsCertificateKeyId" uuid,
    "auditLogsRetentionDays" integer,
    "kmsSecretManagerKeyId" uuid,
    "kmsSecretManagerEncryptedDataKey" bytea
);


ALTER TABLE public.projects OWNER TO infisical;

--
-- Name: rate_limit; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.rate_limit (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "readRateLimit" integer DEFAULT 600 NOT NULL,
    "writeRateLimit" integer DEFAULT 200 NOT NULL,
    "secretsRateLimit" integer DEFAULT 60 NOT NULL,
    "authRateLimit" integer DEFAULT 60 NOT NULL,
    "inviteUserRateLimit" integer DEFAULT 30 NOT NULL,
    "mfaRateLimit" integer DEFAULT 20 NOT NULL,
    "publicEndpointLimit" integer DEFAULT 30 NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.rate_limit OWNER TO infisical;

--
-- Name: saml_configs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.saml_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "authProvider" character varying(255) NOT NULL,
    "isActive" boolean NOT NULL,
    "encryptedEntryPoint" character varying(255),
    "entryPointIV" character varying(255),
    "entryPointTag" character varying(255),
    "encryptedIssuer" character varying(255),
    "issuerTag" character varying(255),
    "issuerIV" character varying(255),
    "encryptedCert" text,
    "certIV" character varying(255),
    "certTag" character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "orgId" uuid NOT NULL,
    "lastUsed" timestamp with time zone
);


ALTER TABLE public.saml_configs OWNER TO infisical;

--
-- Name: scim_tokens; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.scim_tokens (
    id character varying(36) DEFAULT gen_random_uuid() NOT NULL,
    "ttlDays" bigint DEFAULT '365'::bigint NOT NULL,
    description character varying(255) NOT NULL,
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.scim_tokens OWNER TO infisical;

--
-- Name: secret_approval_policies; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    "secretPath" character varying(255),
    approvals integer DEFAULT 1 NOT NULL,
    "envId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "enforcementLevel" character varying(10) DEFAULT 'hard'::character varying NOT NULL
);


ALTER TABLE public.secret_approval_policies OWNER TO infisical;

--
-- Name: secret_approval_policies_approvers; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_policies_approvers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "policyId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "approverUserId" uuid,
    "approverGroupId" uuid
);


ALTER TABLE public.secret_approval_policies_approvers OWNER TO infisical;

--
-- Name: secret_approval_request_secret_tags; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_request_secret_tags (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "secretId" uuid NOT NULL,
    "tagId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_approval_request_secret_tags OWNER TO infisical;

--
-- Name: secret_approval_request_secret_tags_v2; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_request_secret_tags_v2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "secretId" uuid NOT NULL,
    "tagId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_approval_request_secret_tags_v2 OWNER TO infisical;

--
-- Name: secret_approval_requests; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "policyId" uuid NOT NULL,
    "hasMerged" boolean DEFAULT false NOT NULL,
    status character varying(255) DEFAULT 'open'::character varying NOT NULL,
    conflicts jsonb,
    slug character varying(255) NOT NULL,
    "folderId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "isReplicated" boolean,
    "committerUserId" uuid NOT NULL,
    "statusChangedByUserId" uuid,
    "bypassReason" character varying(255)
);


ALTER TABLE public.secret_approval_requests OWNER TO infisical;

--
-- Name: secret_approval_requests_reviewers; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_requests_reviewers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    status character varying(255) NOT NULL,
    "requestId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "reviewerUserId" uuid NOT NULL
);


ALTER TABLE public.secret_approval_requests_reviewers OWNER TO infisical;

--
-- Name: secret_approval_requests_secrets; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_requests_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer DEFAULT 1,
    "secretBlindIndex" text,
    "secretKeyCiphertext" text NOT NULL,
    "secretKeyIV" text NOT NULL,
    "secretKeyTag" text NOT NULL,
    "secretValueCiphertext" text NOT NULL,
    "secretValueIV" text NOT NULL,
    "secretValueTag" text NOT NULL,
    "secretCommentCiphertext" text,
    "secretCommentIV" text,
    "secretCommentTag" text,
    "secretReminderNote" character varying(255),
    "secretReminderRepeatDays" integer,
    "skipMultilineEncoding" boolean DEFAULT false,
    algorithm character varying(255) DEFAULT 'aes-256-gcm'::character varying NOT NULL,
    "keyEncoding" character varying(255) DEFAULT 'utf8'::character varying NOT NULL,
    metadata jsonb,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "requestId" uuid NOT NULL,
    op character varying(255) NOT NULL,
    "secretId" uuid,
    "secretVersion" uuid
);


ALTER TABLE public.secret_approval_requests_secrets OWNER TO infisical;

--
-- Name: secret_approval_requests_secrets_v2; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_approval_requests_secrets_v2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer DEFAULT 1,
    key character varying(500) NOT NULL,
    "encryptedValue" bytea,
    "encryptedComment" bytea,
    "reminderNote" character varying(255),
    "reminderRepeatDays" integer,
    "skipMultilineEncoding" boolean DEFAULT false,
    metadata jsonb,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "requestId" uuid NOT NULL,
    op character varying(255) NOT NULL,
    "secretId" uuid,
    "secretVersion" uuid
);


ALTER TABLE public.secret_approval_requests_secrets_v2 OWNER TO infisical;

--
-- Name: secret_blind_indexes; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_blind_indexes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "encryptedSaltCipherText" text NOT NULL,
    "saltIV" text NOT NULL,
    "saltTag" text NOT NULL,
    algorithm character varying(255) DEFAULT 'aes-256-gcm'::character varying NOT NULL,
    "keyEncoding" character varying(255) DEFAULT 'utf8'::character varying NOT NULL,
    "projectId" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_blind_indexes OWNER TO infisical;

--
-- Name: secret_folder_versions; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_folder_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    version integer DEFAULT 1,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "envId" uuid NOT NULL,
    "folderId" uuid NOT NULL
);


ALTER TABLE public.secret_folder_versions OWNER TO infisical;

--
-- Name: secret_folders; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_folders (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    version integer DEFAULT 1,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "envId" uuid NOT NULL,
    "parentId" uuid,
    "isReserved" boolean DEFAULT false
);


ALTER TABLE public.secret_folders OWNER TO infisical;

--
-- Name: secret_imports; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_imports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer DEFAULT 1,
    "importPath" character varying(255) NOT NULL,
    "importEnv" uuid NOT NULL,
    "position" integer NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "folderId" uuid NOT NULL,
    "isReplication" boolean DEFAULT false,
    "isReplicationSuccess" boolean,
    "replicationStatus" text,
    "lastReplicated" timestamp with time zone,
    "isReserved" boolean DEFAULT false
);


ALTER TABLE public.secret_imports OWNER TO infisical;

--
-- Name: secret_references; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_references (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment character varying(255) NOT NULL,
    "secretPath" character varying(255) NOT NULL,
    "secretId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_references OWNER TO infisical;

--
-- Name: secret_references_v2; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_references_v2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment character varying(255) NOT NULL,
    "secretPath" character varying(255) NOT NULL,
    "secretKey" character varying(500) NOT NULL,
    "secretId" uuid NOT NULL
);


ALTER TABLE public.secret_references_v2 OWNER TO infisical;

--
-- Name: secret_rotation_output_v2; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_rotation_output_v2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key character varying(255) NOT NULL,
    "secretId" uuid NOT NULL,
    "rotationId" uuid NOT NULL
);


ALTER TABLE public.secret_rotation_output_v2 OWNER TO infisical;

--
-- Name: secret_rotation_outputs; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_rotation_outputs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key character varying(255) NOT NULL,
    "secretId" uuid NOT NULL,
    "rotationId" uuid NOT NULL
);


ALTER TABLE public.secret_rotation_outputs OWNER TO infisical;

--
-- Name: secret_rotations; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_rotations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider character varying(255) NOT NULL,
    "secretPath" character varying(255) NOT NULL,
    "interval" integer NOT NULL,
    "lastRotatedAt" timestamp with time zone,
    status character varying(255),
    "statusMessage" text,
    "encryptedData" text,
    "encryptedDataIV" text,
    "encryptedDataTag" text,
    algorithm character varying(255),
    "keyEncoding" character varying(255),
    "envId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_rotations OWNER TO infisical;

--
-- Name: secret_scanning_git_risks; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_scanning_git_risks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    description character varying(255),
    "startLine" character varying(255),
    "endLine" character varying(255),
    "startColumn" character varying(255),
    "endColumn" character varying(255),
    file character varying(255),
    "symlinkFile" character varying(255),
    commit character varying(255),
    entropy character varying(255),
    author character varying(255),
    email character varying(255),
    date character varying(255),
    message text,
    tags text[],
    "ruleID" character varying(255),
    fingerprint character varying(255),
    "fingerPrintWithoutCommitId" character varying(255),
    "isFalsePositive" boolean DEFAULT false,
    "isResolved" boolean DEFAULT false,
    "riskOwner" character varying(255),
    "installationId" character varying(255) NOT NULL,
    "repositoryId" character varying(255),
    "repositoryLink" character varying(255),
    "repositoryFullName" character varying(255),
    "pusherName" character varying(255),
    "pusherEmail" character varying(255),
    status character varying(255),
    "orgId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_scanning_git_risks OWNER TO infisical;

--
-- Name: secret_sharing; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_sharing (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "encryptedValue" character varying(255),
    iv character varying(255),
    tag character varying(255),
    "hashedHex" character varying(255),
    "expiresAt" timestamp with time zone NOT NULL,
    "userId" uuid,
    "orgId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "expiresAfterViews" integer,
    "accessType" character varying(255) DEFAULT 'anyone'::character varying NOT NULL,
    name character varying(255),
    "lastViewedAt" timestamp with time zone,
    password character varying(255),
    "encryptedSecret" bytea,
    identifier character varying(64)
);


ALTER TABLE public.secret_sharing OWNER TO infisical;

--
-- Name: secret_snapshot_folders; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_snapshot_folders (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "envId" uuid NOT NULL,
    "folderVersionId" uuid NOT NULL,
    "snapshotId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_snapshot_folders OWNER TO infisical;

--
-- Name: secret_snapshot_secrets; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_snapshot_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "envId" uuid NOT NULL,
    "secretVersionId" uuid NOT NULL,
    "snapshotId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_snapshot_secrets OWNER TO infisical;

--
-- Name: secret_snapshot_secrets_v2; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_snapshot_secrets_v2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "envId" uuid NOT NULL,
    "secretVersionId" uuid NOT NULL,
    "snapshotId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_snapshot_secrets_v2 OWNER TO infisical;

--
-- Name: secret_snapshots; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_snapshots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "envId" uuid NOT NULL,
    "folderId" uuid NOT NULL,
    "parentFolderId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_snapshots OWNER TO infisical;

--
-- Name: secret_tag_junction; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_tag_junction (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "secretsId" uuid NOT NULL,
    "secret_tagsId" uuid NOT NULL
);


ALTER TABLE public.secret_tag_junction OWNER TO infisical;

--
-- Name: secret_tags; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_tags (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug character varying(255) NOT NULL,
    color character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "createdBy" uuid,
    "projectId" character varying(255) NOT NULL,
    "createdByActorType" character varying(255) DEFAULT 'user'::character varying NOT NULL
);


ALTER TABLE public.secret_tags OWNER TO infisical;

--
-- Name: secret_v2_tag_junction; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_v2_tag_junction (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "secrets_v2Id" uuid NOT NULL,
    "secret_tagsId" uuid NOT NULL
);


ALTER TABLE public.secret_v2_tag_junction OWNER TO infisical;

--
-- Name: secret_version_tag_junction; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_version_tag_junction (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "secret_versionsId" uuid NOT NULL,
    "secret_tagsId" uuid NOT NULL
);


ALTER TABLE public.secret_version_tag_junction OWNER TO infisical;

--
-- Name: secret_version_v2_tag_junction; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_version_v2_tag_junction (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "secret_versions_v2Id" uuid NOT NULL,
    "secret_tagsId" uuid NOT NULL
);


ALTER TABLE public.secret_version_v2_tag_junction OWNER TO infisical;

--
-- Name: secret_versions; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    type character varying(255) DEFAULT 'shared'::character varying NOT NULL,
    "secretBlindIndex" text,
    "secretKeyCiphertext" text NOT NULL,
    "secretKeyIV" text NOT NULL,
    "secretKeyTag" text NOT NULL,
    "secretValueCiphertext" text NOT NULL,
    "secretValueIV" text NOT NULL,
    "secretValueTag" text NOT NULL,
    "secretCommentCiphertext" text,
    "secretCommentIV" text,
    "secretCommentTag" text,
    "secretReminderNote" character varying(255),
    "secretReminderRepeatDays" integer,
    "skipMultilineEncoding" boolean DEFAULT false,
    algorithm character varying(255) DEFAULT 'aes-256-gcm'::character varying NOT NULL,
    "keyEncoding" character varying(255) DEFAULT 'utf8'::character varying NOT NULL,
    metadata jsonb,
    "envId" uuid,
    "secretId" uuid NOT NULL,
    "folderId" uuid NOT NULL,
    "userId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_versions OWNER TO infisical;

--
-- Name: secret_versions_v2; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secret_versions_v2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    type character varying(255) DEFAULT 'shared'::character varying NOT NULL,
    key character varying(500) NOT NULL,
    "encryptedValue" bytea,
    "encryptedComment" bytea,
    "reminderNote" character varying(255),
    "reminderRepeatDays" integer,
    "skipMultilineEncoding" boolean DEFAULT false,
    metadata jsonb,
    "envId" uuid,
    "secretId" uuid NOT NULL,
    "folderId" uuid NOT NULL,
    "userId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secret_versions_v2 OWNER TO infisical;

--
-- Name: secrets; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    type character varying(255) DEFAULT 'shared'::character varying NOT NULL,
    "secretBlindIndex" text,
    "secretKeyCiphertext" text NOT NULL,
    "secretKeyIV" text NOT NULL,
    "secretKeyTag" text NOT NULL,
    "secretValueCiphertext" text NOT NULL,
    "secretValueIV" text NOT NULL,
    "secretValueTag" text NOT NULL,
    "secretCommentCiphertext" text,
    "secretCommentIV" text,
    "secretCommentTag" text,
    "secretReminderNote" character varying(255),
    "secretReminderRepeatDays" integer,
    "skipMultilineEncoding" boolean DEFAULT false,
    algorithm character varying(255) DEFAULT 'aes-256-gcm'::character varying NOT NULL,
    "keyEncoding" character varying(255) DEFAULT 'utf8'::character varying NOT NULL,
    metadata jsonb,
    "userId" uuid,
    "folderId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secrets OWNER TO infisical;

--
-- Name: secrets_v2; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.secrets_v2 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    type character varying(255) DEFAULT 'shared'::character varying NOT NULL,
    key character varying(500) NOT NULL,
    "encryptedValue" bytea,
    "encryptedComment" bytea,
    "reminderNote" character varying(255),
    "reminderRepeatDays" integer,
    "skipMultilineEncoding" boolean DEFAULT false,
    metadata jsonb,
    "userId" uuid,
    "folderId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.secrets_v2 OWNER TO infisical;

--
-- Name: service_tokens; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.service_tokens (
    id character varying(36) DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    scopes jsonb NOT NULL,
    permissions text[] NOT NULL,
    "lastUsed" timestamp with time zone,
    "expiresAt" timestamp with time zone,
    "secretHash" text NOT NULL,
    "encryptedKey" text,
    iv text,
    tag text,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "createdBy" character varying(255) NOT NULL,
    "projectId" character varying(255) NOT NULL
);


ALTER TABLE public.service_tokens OWNER TO infisical;

--
-- Name: slack_integrations; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.slack_integrations (
    id uuid NOT NULL,
    "teamId" character varying(255) NOT NULL,
    "teamName" character varying(255) NOT NULL,
    "slackUserId" character varying(255) NOT NULL,
    "slackAppId" character varying(255) NOT NULL,
    "encryptedBotAccessToken" bytea NOT NULL,
    "slackBotId" character varying(255) NOT NULL,
    "slackBotUserId" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.slack_integrations OWNER TO infisical;

--
-- Name: super_admin; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.super_admin (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    initialized boolean DEFAULT false,
    "allowSignUp" boolean DEFAULT true,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "allowedSignUpDomain" character varying(255),
    "instanceId" uuid DEFAULT gen_random_uuid() NOT NULL,
    "trustSamlEmails" boolean DEFAULT false,
    "trustLdapEmails" boolean DEFAULT false,
    "trustOidcEmails" boolean DEFAULT false,
    "defaultAuthOrgId" uuid,
    "enabledLoginMethods" text[],
    "encryptedSlackClientId" bytea,
    "encryptedSlackClientSecret" bytea
);


ALTER TABLE public.super_admin OWNER TO infisical;

--
-- Name: trusted_ips; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.trusted_ips (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "ipAddress" character varying(255) NOT NULL,
    type character varying(255) NOT NULL,
    prefix integer,
    "isActive" boolean DEFAULT true,
    comment character varying(255),
    "projectId" character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.trusted_ips OWNER TO infisical;

--
-- Name: user_actions; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.user_actions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action character varying(255) NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "userId" uuid NOT NULL
);


ALTER TABLE public.user_actions OWNER TO infisical;

--
-- Name: user_aliases; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.user_aliases (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "userId" uuid NOT NULL,
    username character varying(255),
    "aliasType" character varying(255) NOT NULL,
    "externalId" character varying(255) NOT NULL,
    emails text[],
    "orgId" uuid,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.user_aliases OWNER TO infisical;

--
-- Name: user_encryption_keys; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.user_encryption_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "clientPublicKey" text,
    "serverPrivateKey" text,
    "encryptionVersion" integer DEFAULT 2,
    "protectedKey" text,
    "protectedKeyIV" text,
    "protectedKeyTag" text,
    "publicKey" text NOT NULL,
    "encryptedPrivateKey" text NOT NULL,
    iv text NOT NULL,
    tag text NOT NULL,
    salt text NOT NULL,
    verifier text NOT NULL,
    "userId" uuid NOT NULL,
    "hashedPassword" character varying(255),
    "serverEncryptedPrivateKey" text,
    "serverEncryptedPrivateKeyIV" text,
    "serverEncryptedPrivateKeyTag" text,
    "serverEncryptedPrivateKeyEncoding" text
);


ALTER TABLE public.user_encryption_keys OWNER TO infisical;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.user_group_membership (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "userId" uuid NOT NULL,
    "groupId" uuid NOT NULL,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "isPending" boolean DEFAULT false NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO infisical;

--
-- Name: users; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255),
    "authMethods" text[],
    "superAdmin" boolean DEFAULT false,
    "firstName" character varying(255),
    "lastName" character varying(255),
    "isAccepted" boolean DEFAULT false,
    "isMfaEnabled" boolean DEFAULT false,
    "mfaMethods" text[],
    devices jsonb,
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "isGhost" boolean DEFAULT false NOT NULL,
    username character varying(255) NOT NULL,
    "isEmailVerified" boolean DEFAULT false,
    "consecutiveFailedMfaAttempts" integer DEFAULT 0,
    "isLocked" boolean DEFAULT false,
    "temporaryLockDateEnd" timestamp with time zone,
    "consecutiveFailedPasswordAttempts" integer DEFAULT 0
);


ALTER TABLE public.users OWNER TO infisical;

--
-- Name: webhooks; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.webhooks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "secretPath" character varying(255) DEFAULT '/'::character varying NOT NULL,
    url character varying(255) NOT NULL,
    "lastStatus" character varying(255),
    "lastRunErrorMessage" text,
    "isDisabled" boolean DEFAULT false NOT NULL,
    "encryptedSecretKey" text,
    iv text,
    tag text,
    algorithm character varying(255),
    "keyEncoding" character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "envId" uuid NOT NULL,
    "urlCipherText" text,
    "urlIV" character varying(255),
    "urlTag" character varying(255),
    type character varying(255) DEFAULT 'general'::character varying
);


ALTER TABLE public.webhooks OWNER TO infisical;

--
-- Name: workflow_integrations; Type: TABLE; Schema: public; Owner: infisical
--

CREATE TABLE public.workflow_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration character varying(255) NOT NULL,
    slug character varying(255) NOT NULL,
    "orgId" uuid NOT NULL,
    description character varying(255),
    "createdAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updatedAt" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.workflow_integrations OWNER TO infisical;

--
-- Name: infisical_migrations id; Type: DEFAULT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.infisical_migrations ALTER COLUMN id SET DEFAULT nextval('public.infisical_migrations_id_seq'::regclass);


--
-- Name: infisical_migrations_lock index; Type: DEFAULT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.infisical_migrations_lock ALTER COLUMN index SET DEFAULT nextval('public.infisical_migrations_lock_index_seq'::regclass);


--
-- Data for Name: access_approval_policies; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.access_approval_policies (id, name, approvals, "secretPath", "envId", "createdAt", "updatedAt", "enforcementLevel") FROM stdin;
\.


--
-- Data for Name: access_approval_policies_approvers; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.access_approval_policies_approvers (id, "policyId", "createdAt", "updatedAt", "approverUserId", "approverGroupId") FROM stdin;
\.


--
-- Data for Name: access_approval_requests; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.access_approval_requests (id, "policyId", "privilegeId", "requestedBy", "isTemporary", "temporaryRange", permissions, "createdAt", "updatedAt", "requestedByUserId") FROM stdin;
\.


--
-- Data for Name: access_approval_requests_reviewers; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.access_approval_requests_reviewers (id, member, status, "requestId", "createdAt", "updatedAt", "reviewerUserId") FROM stdin;
\.


--
-- Data for Name: api_keys; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.api_keys (id, name, "lastUsed", "expiresAt", "secretHash", "createdAt", "updatedAt", "userId") FROM stdin;
\.


--
-- Data for Name: audit_log_streams; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.audit_log_streams (id, url, "encryptedHeadersCiphertext", "encryptedHeadersIV", "encryptedHeadersTag", "encryptedHeadersAlgorithm", "encryptedHeadersKeyEncoding", "orgId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.audit_logs (id, actor, "actorMetadata", "ipAddress", "eventType", "eventMetadata", "userAgent", "userAgentType", "expiresAt", "createdAt", "updatedAt", "orgId", "projectId", "projectName") FROM stdin;
\.


--
-- Data for Name: auth_token_sessions; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.auth_token_sessions (id, ip, "userAgent", "refreshVersion", "accessVersion", "lastUsed", "createdAt", "updatedAt", "userId") FROM stdin;
6f4d99d6-0aed-455c-b548-07e6a246d9e2	10.42.0.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0	2	2	2025-10-22 15:25:08.39+00	2025-10-22 15:25:08.391039+00	2025-10-22 15:28:36.978017+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
6422e1ed-0ffa-4ce3-b2f7-a3a52e44981c	10.42.0.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0	1	1	2025-10-22 15:33:05.654+00	2025-10-22 15:33:05.652338+00	2025-10-22 15:33:05.652338+00	00155375-154c-4c18-8331-92a36dc7ff1b
423d0292-b287-45ea-b47b-670c08b8ef62	10.42.0.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0	1	1	2025-11-11 19:16:46.802+00	2025-11-11 19:16:46.802884+00	2025-11-11 19:16:46.802884+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
886ec605-08a6-4210-8666-f2137b58c526	10.42.0.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0	1	1	2025-12-10 16:46:39.892+00	2025-12-10 16:46:39.89015+00	2025-12-10 16:46:39.89015+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
d9f148f6-14b1-426b-a769-8dd4ae19cd6c	186.68.104.126	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0	1	1	2025-12-16 21:18:18.538+00	2025-12-16 21:18:18.548065+00	2025-12-16 21:18:18.548065+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
abf69936-217e-4779-ace0-c7cc6d45a7ca	10.42.1.0	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0	1	1	2025-12-16 22:01:10.143+00	2025-12-16 22:01:10.144206+00	2025-12-16 22:01:10.144206+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
456015fd-67a5-444c-a600-f8297c20b6f7	10.42.1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0	1	1	2025-12-16 23:34:17.782+00	2025-12-16 23:34:17.790177+00	2025-12-16 23:34:17.790177+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
e6c6ffc5-eb57-4446-877a-563c4f4c16e0	181.39.233.78	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0	1	1	2025-12-22 19:16:43.4+00	2025-12-22 19:16:43.406838+00	2025-12-22 19:16:43.406838+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
e8a4036f-1174-46a8-a860-8026336b646f	181.39.233.78	cli	1	1	2025-12-22 19:43:11.111+00	2025-12-22 19:43:11.111688+00	2025-12-22 19:43:11.111688+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
50c876ae-8195-48f2-9cd0-fd8d16481689	181.39.233.78	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0	1	1	2025-12-22 20:10:31.021+00	2025-12-22 20:10:31.013201+00	2025-12-22 20:10:31.013201+00	00155375-154c-4c18-8331-92a36dc7ff1b
\.


--
-- Data for Name: auth_tokens; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.auth_tokens (id, type, "phoneNumber", "tokenHash", "triesLeft", "expiresAt", "createdAt", "updatedAt", "userId", "orgId") FROM stdin;
\.


--
-- Data for Name: backup_private_key; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.backup_private_key (id, "encryptedPrivateKey", iv, tag, algorithm, "keyEncoding", salt, verifier, "createdAt", "updatedAt", "userId") FROM stdin;
93b8068c-68f8-41d0-ab5e-3555588143a6	ll1YYM9b0XGHV4/9lkNE3hoZU/n18EHLoL5bqvgGC+DEuDzVjXuiB9vpVbg=	wwnGMxjH9MYKIZYzEBm3eg==	ygU9cPrtmIQ6WeZ18UNCUQ==	aes-256-gcm	utf8	f11ff01343c682759e42698c4c49d46fce9ab114c8f643727470e7c02f978720	58543ae202065007c2bcd67bafb208e9a472a51c003aa815b4a89ce2bf38c9d9e62d52a2e1faae21cdb42bb1be2e140603210a171fcf740fb36cc77c527d3c89b569f86d11a1f8b9fc859f85398213fa22a176201de9ce9e8a4c137dc1841f2ed75aa965458af9364d0c01da3f7af61843bde124ee1323ad8786efd9f26843c7b998a56f025314fb21846844404c7cb1307ecea17588846388da74f7c360f8fc84b1bf660550e7e9a7e46db6afb252aaf278d1588d6276c6ed44dfa778960ad01a7786ca2abbfadf5cdb43d2bfa0c7ccd1ddc31b1c0dd9d2d1649d0eb01f3ca9c90cb53f680e705d53cd3ca6ed8c5f532a0a24982b7c69b6fbe98d4f8b3ac8cf548a973dbfd431ac76f4067a54d39e3e8a1e450f612eac115235a725a302167cf07415822053173ede8f96fbab92fb6f6e18b1bd209139944c5ae505d6aef535592e355e80dccdfee1477c7b61605a54f070f2b11882b2e0152ef040ed06efe74a028f835aea7ae6e75244057c9e5e15f911a63e5603c2b86f161e6473840b7f859fedc8cb80f3b7b9921544b96a2d44d5776e911bd2393740fe3491cc3f2c8be997467e38c6e885b75cb2d2f7833f64754c70121a387fb7a3c842be617a67175a28623dbe9b8ded146fde70efc31625a41cf9efdb2971f7617e3a25ba337f189a5000528f8cf25939bcd2bc9486840480f7706ea25fec3a924710501571af12	2025-10-22 15:25:16.125575+00	2025-10-22 15:25:16.126+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
c6c8cc65-9ef5-45b1-ba9f-890c08c7b035	QWkFuLkYHeuF4bOdIfzKy8gREVPdwH9sfxoRj1u07F6La+HVDDb1B8L8gY0=	BiqjokD49GEDqTJsD7qXvA==	XkCdCUfDRdlxzYMTMkiM4g==	aes-256-gcm	utf8	e631746badc93288a3f1c1201a7e6d16d89d198bdbc9574e1850d27601ea53bc	f8d30cda3e3c4217f8690255d67f646a7e5de24eb643ce779a1132120f99e9138281c50b7c82c1f4854af68c2eb41df3e26634a46fd5754ff045ddca425dd53c2bf6bcaa913b47d90c131fe6fc4fb78f4c9ff5dd41ee04fd3cc1d224b1ec6084271993ba9893f925392c9123a75cb9e294906351d859db0f014c2e2c9024d09da26244e72466c78113c054f19532ea755f028adbde462b0c35b2bf6d4a21e7e73a15de13aee72d59b005c52da06154ed15a7cc6aa46fbd02a7f901e0fb9f9ca793bdd559ad430ff41844421b3ad5a7ed20099266dc96399466906a775bacd4a3b7bdc5e308a3e6f683a55af6a1c2571b65ed033c628f1af0c2c0d7185e484e9246abdbbd2754917e59e7e6f74e8db0135319288e7cd53cb1a67675c47851d8eac9554a3d0592d8eabbe9e35e9050f203eb77eacc7e25d51fc3767e6186acb30ecf70ac508cdb4493435c939b1c92fc50fc297873a58dd103a8ca44afafd7147ea09ba5f8517a0c0d3621d6b6388f605e8aa32701efe3e46801012694c9c6d61a0422b7704f4ca7ca3ffc94fa3ac701ee8ce5ecb652c1d3f17bc36ec567b2d3eea6dcd4ebc52f22c777a2a0729c9e0cb015b536a3a13f63cda08c15a3b319fd1ce7aa71774ea3946b8d376c83c17074270df51ff7ecf1bfa26dbb4917f43a5a9adb5a6ec43c11126d8a40bb39ec48581e72a99bcd1d69e5ed16f968c6a4c3fd12	2025-10-22 15:33:07.745472+00	2025-10-22 15:33:07.757+00	00155375-154c-4c18-8331-92a36dc7ff1b
\.


--
-- Data for Name: certificate_authorities; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificate_authorities (id, "createdAt", "updatedAt", "parentCaId", "projectId", type, status, "friendlyName", organization, ou, country, province, locality, "commonName", dn, "serialNumber", "maxPathLength", "keyAlgorithm", "notBefore", "notAfter", "activeCaCertId", "requireTemplateForIssuance") FROM stdin;
\.


--
-- Data for Name: certificate_authority_certs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificate_authority_certs (id, "createdAt", "updatedAt", "caId", "encryptedCertificate", "encryptedCertificateChain", version, "caSecretId") FROM stdin;
\.


--
-- Data for Name: certificate_authority_crl; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificate_authority_crl (id, "createdAt", "updatedAt", "caId", "encryptedCrl", "caSecretId") FROM stdin;
\.


--
-- Data for Name: certificate_authority_secret; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificate_authority_secret (id, "createdAt", "updatedAt", "caId", "encryptedPrivateKey") FROM stdin;
\.


--
-- Data for Name: certificate_bodies; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificate_bodies (id, "createdAt", "updatedAt", "certId", "encryptedCertificate") FROM stdin;
\.


--
-- Data for Name: certificate_template_est_configs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificate_template_est_configs (id, "certificateTemplateId", "encryptedCaChain", "hashedPassphrase", "isEnabled", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: certificate_templates; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificate_templates (id, "caId", "pkiCollectionId", name, "commonName", "subjectAlternativeName", ttl, "createdAt", "updatedAt", "keyUsages", "extendedKeyUsages") FROM stdin;
\.


--
-- Data for Name: certificates; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.certificates (id, "createdAt", "updatedAt", "caId", status, "serialNumber", "friendlyName", "commonName", "notBefore", "notAfter", "revokedAt", "revocationReason", "altNames", "caCertId", "certificateTemplateId", "keyUsages", "extendedKeyUsages") FROM stdin;
\.


--
-- Data for Name: dynamic_secret_leases; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.dynamic_secret_leases (id, version, "externalEntityId", "expireAt", status, "statusDetails", "dynamicSecretId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: dynamic_secrets; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.dynamic_secrets (id, name, version, type, "defaultTTL", "maxTTL", "inputIV", "inputCiphertext", "inputTag", algorithm, "keyEncoding", "folderId", status, "statusDetails", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: external_group_org_role_mappings; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.external_group_org_role_mappings (id, "groupName", role, "roleId", "orgId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: external_kms; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.external_kms (id, provider, "encryptedProviderInputs", status, "statusDetails", "kmsKeyId") FROM stdin;
\.


--
-- Data for Name: git_app_install_sessions; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.git_app_install_sessions (id, "sessionId", "userId", "orgId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: git_app_org; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.git_app_org (id, "installationId", "userId", "orgId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: group_project_membership_roles; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.group_project_membership_roles (id, role, "projectMembershipId", "customRoleId", "isTemporary", "temporaryMode", "temporaryRange", "temporaryAccessStartTime", "temporaryAccessEndTime", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: group_project_memberships; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.group_project_memberships (id, "projectId", "groupId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: groups; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.groups (id, "orgId", name, slug, role, "roleId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: identities; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identities (id, name, "authMethod", "createdAt", "updatedAt") FROM stdin;
b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	Docker	\N	2025-10-22 15:54:01.84996+00	2025-10-22 15:54:01.84996+00
a33a0079-5945-4e32-9987-14f21d2e5236	Kubernetes	\N	2025-11-11 19:25:24.472415+00	2025-11-11 19:25:24.472415+00
\.


--
-- Data for Name: identity_access_tokens; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_access_tokens (id, "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUses", "accessTokenNumUsesLimit", "accessTokenLastUsedAt", "accessTokenLastRenewedAt", "isAccessTokenRevoked", "identityUAClientSecretId", "identityId", "createdAt", "updatedAt", name, "authMethod") FROM stdin;
f3a450db-6920-440b-9091-54093744fc74	2592000	2592000	29017	0	2025-12-05 20:36:27.571+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-02 11:06:16.239119+00	2025-12-05 20:36:44.170378+00	\N	kubernetes-auth
a99ef4e9-ae79-4d0d-8880-1f05d2135212	2592000	2592000	1	0	2025-12-04 16:16:13.525+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:16:13.413633+00	2025-12-04 16:17:07.034344+00	\N	universal-auth
49c8708c-7f81-4bf7-a201-b3d6b480aaff	2592000	2592000	1	0	2025-12-04 16:16:29.334+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:16:29.243316+00	2025-12-04 16:17:25.174835+00	\N	universal-auth
171c5eb6-48c5-4f51-a3fc-3a5c5ac75cec	2592000	2592000	10	0	2025-12-16 21:22:48.197+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-16 21:21:15.426866+00	2025-12-16 21:23:24.80997+00	\N	kubernetes-auth
0b9ef666-6be4-497c-bbc2-4a2563c0dd1f	2592000	2592000	1	0	2025-12-04 16:17:53.422+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:17:53.319559+00	2025-12-04 16:18:51.600397+00	\N	universal-auth
73ff7978-81ab-4c8e-b9ec-e33d4495d90f	2592000	2592000	1	0	2025-12-04 16:18:32.349+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:18:32.232096+00	2025-12-04 16:19:28.499264+00	\N	universal-auth
82e1cb4f-4f96-474c-8534-9ee389ca2b1e	2592000	2592000	1	0	2025-12-04 16:22:37.441+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:22:37.329595+00	2025-12-04 16:23:31.660917+00	\N	universal-auth
025493c2-0bf9-4641-8dec-0816da7aa6d3	2592000	2592000	1	0	2025-12-04 16:24:32.24+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:24:32.145364+00	2025-12-04 16:25:33.212497+00	\N	universal-auth
0266d72c-1e6d-4c16-875a-26d7ad4612cf	2592000	2592000	1	0	2025-12-04 16:24:39.784+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:24:39.701704+00	2025-12-04 16:25:44.062963+00	\N	universal-auth
8d0ce584-8390-4de9-b60b-0eec600b3c87	2592000	2592000	1	0	2025-12-04 16:27:35.853+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:27:35.753906+00	2025-12-04 16:28:26.123203+00	\N	universal-auth
3f3bc1dc-af79-43be-902e-af4fd975c673	2592000	2592000	1	0	2025-12-04 16:29:00.592+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:29:00.463788+00	2025-12-04 16:30:05.949232+00	\N	universal-auth
12e9c75c-6aeb-4def-bbe7-5256bf4793ad	2592000	2592000	191	0	2025-12-08 18:50:37.742+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-08 18:18:40.186017+00	2025-12-08 18:50:48.972283+00	\N	kubernetes-auth
fccd915d-e35c-445b-a743-df55823c4b74	2592000	2592000	1	0	2025-12-02 16:05:29.593+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 16:05:29.505225+00	2025-12-02 16:06:25.421896+00	\N	universal-auth
c1b23786-ee13-4ac8-813d-4e1101da4d3f	2592000	2592000	1	0	2025-12-02 16:05:34.008+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 16:05:33.902807+00	2025-12-02 16:06:36.987191+00	\N	universal-auth
b1a1d100-805e-44d8-bd11-dc406b410791	2592000	2592000	1	0	2025-12-02 16:07:14.442+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 16:07:14.35266+00	2025-12-02 16:08:11.974581+00	\N	universal-auth
8ea8f817-f0b8-4caf-b86b-13ac5f439c78	2592000	2592000	1	0	2025-12-02 16:50:44.306+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 16:50:44.196365+00	2025-12-02 16:51:35.504611+00	\N	universal-auth
8def32d6-bb78-4d8c-b4bf-4621672ff196	2592000	2592000	1	0	2025-12-04 16:16:21.823+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:16:21.71037+00	2025-12-04 16:17:27.336741+00	\N	universal-auth
6d49981c-b341-4adc-9940-2b5edaaefcb7	2592000	2592000	1	0	2025-12-04 16:16:40.356+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:16:40.23629+00	2025-12-04 16:17:36.785206+00	\N	universal-auth
9bedac42-ee0d-4695-9a88-51bcef4a8924	2592000	2592000	1	0	2025-12-04 16:17:25.137+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:17:25.024507+00	2025-12-04 16:18:29.877915+00	\N	universal-auth
c9c6620c-04a6-4fab-b3ec-6879c43ae9a2	2592000	2592000	1	0	2025-12-04 16:18:01.153+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:18:01.036628+00	2025-12-04 16:19:04.47101+00	\N	universal-auth
b494ddfe-f949-423c-8319-a9327c1aec7b	2592000	2592000	1	0	2025-12-04 16:18:26.117+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:18:26.013461+00	2025-12-04 16:19:35.034435+00	\N	universal-auth
d49200db-2390-4cdd-967c-bf57ee39ec46	2592000	2592000	1	0	2025-12-04 16:18:41.543+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:18:41.450462+00	2025-12-04 16:19:48.301412+00	\N	universal-auth
af859c68-d5f9-443c-96d2-6238d7669240	2592000	2592000	1	0	2025-12-04 16:22:22.517+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:22:22.402623+00	2025-12-04 16:23:25.931867+00	\N	universal-auth
ff1d238f-861f-4506-8d51-361863830d1c	2592000	2592000	1	0	2025-12-04 16:25:02.778+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:25:02.664064+00	2025-12-04 16:25:56.12904+00	\N	universal-auth
ccb03ed9-d65c-4efb-ba7a-525e04b4eb53	2592000	2592000	1	0	2025-12-04 16:25:10.485+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:25:10.391542+00	2025-12-04 16:26:19.246833+00	\N	universal-auth
ebb909e7-af8f-43a0-8ef5-adecd55191da	2592000	2592000	1	0	2025-12-04 16:27:45.338+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:27:45.210789+00	2025-12-04 16:28:37.880261+00	\N	universal-auth
27137512-a895-4737-ad5d-19a155412689	2592000	2592000	1	0	2025-12-04 16:27:52.954+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:27:52.865496+00	2025-12-04 16:28:59.400458+00	\N	universal-auth
8aca657d-cfc3-4893-b66d-77447135b34b	2592000	2592000	1	0	2025-12-04 16:28:08.744+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:28:08.63573+00	2025-12-04 16:29:02.71494+00	\N	universal-auth
06f828b8-0933-4d2d-a9fc-a5156db652c9	2592000	2592000	1	0	2025-12-04 16:28:52.318+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:28:52.189295+00	2025-12-04 16:29:52.1749+00	\N	universal-auth
faa66af8-7ca7-4e66-b8b8-88a2ad9fff00	2592000	2592000	1	0	2025-12-04 16:44:14.367+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:44:14.248541+00	2025-12-04 16:45:13.143621+00	\N	universal-auth
1e12cb3a-083d-405b-b6b5-beb68b5af8ba	2592000	2592000	1	0	2025-12-04 16:45:18.791+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:45:18.671283+00	2025-12-04 16:46:19.186707+00	\N	universal-auth
ab1d3171-a36e-4772-bc5d-e4935966449d	2592000	2592000	1	0	2025-12-04 16:45:40.384+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:45:40.270806+00	2025-12-04 16:46:45.833695+00	\N	universal-auth
087abab6-fbcc-49d9-9179-7fc5e8c7f05a	2592000	2592000	57331	0	2025-12-23 19:06:59.092+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-16 21:22:52.512272+00	2025-12-23 19:07:08.674435+00	\N	kubernetes-auth
4e93c07e-0053-4380-95f8-28f70c6e83cd	2592000	2592000	67	0	2025-12-08 19:01:45.81+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-08 18:50:38.009198+00	2025-12-08 19:02:05.490892+00	\N	kubernetes-auth
b4634829-06cc-4e0d-9db0-41824f9dedde	2592000	2592000	1	0	2025-12-02 16:50:24.607+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 16:50:24.458569+00	2025-12-02 16:51:25.858028+00	\N	universal-auth
3b6ff7b6-d92a-4eef-8841-84f14a164c42	2592000	2592000	1	0	2025-12-02 16:50:30.114+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 16:50:29.975138+00	2025-12-02 16:51:26.461373+00	\N	universal-auth
f32c7723-ea0e-459e-bd1f-03a62d2d0e51	2592000	2592000	1	0	2025-12-04 16:44:33.635+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:44:33.495873+00	2025-12-04 16:45:26.311197+00	\N	universal-auth
3c744513-85e2-4ae4-b7dd-0c84bceb3d85	2592000	2592000	1	0	2025-12-04 16:44:24.284+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:44:24.164914+00	2025-12-04 16:45:32.744659+00	\N	universal-auth
0a759019-5637-4b9c-a759-332092ae8821	2592000	2592000	1	0	2025-12-04 16:44:44.679+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:44:44.530485+00	2025-12-04 16:45:51.036334+00	\N	universal-auth
4f9b64b2-b193-4550-9a99-b25300a97716	2592000	2592000	1	0	2025-12-04 16:45:31.636+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:45:31.515364+00	2025-12-04 16:46:27.027479+00	\N	universal-auth
95bad459-eed7-4240-8c62-9cac9d0723b9	2592000	2592000	1	0	2025-12-04 16:46:54.413+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:46:54.29475+00	2025-12-04 16:48:04.044965+00	\N	universal-auth
2bd60d53-450f-4391-93fb-45b4bec850e1	2592000	2592000	42	0	2025-12-08 19:08:58.156+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-08 19:02:03.041699+00	2025-12-08 19:09:57.654976+00	\N	kubernetes-auth
ca6e3cff-3d64-4ad2-a95c-107c534fce85	2592000	2592000	1	0	2025-12-02 18:51:36.774+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 18:51:36.682907+00	2025-12-02 18:52:28.73834+00	\N	universal-auth
8c5dec04-58fe-48df-ae28-84b1def94447	2592000	2592000	1	0	2025-12-02 19:13:10.794+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 19:13:10.685601+00	2025-12-02 19:14:06.370771+00	\N	universal-auth
17a2251e-14db-4228-a2e0-67c7d2fc51cc	2592000	2592000	1	0	2025-12-02 19:13:17.593+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 19:13:17.384976+00	2025-12-02 19:14:21.848501+00	\N	universal-auth
e578785f-0ed9-44d7-99d1-e50a860c147c	2592000	2592000	1	0	2025-12-02 19:32:06.419+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 19:32:06.305597+00	2025-12-02 19:33:14.698008+00	\N	universal-auth
085d0dce-aeda-4f4a-9d52-ef4b8d9262a2	2592000	2592000	1	0	2025-12-04 17:19:55.465+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:19:54.843535+00	2025-12-04 17:20:47.518943+00	\N	universal-auth
ba096a19-c290-4370-a4f8-84eae9fc8b3d	2592000	2592000	1	0	2025-12-04 17:20:08.43+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:20:08.322681+00	2025-12-04 17:21:05.697512+00	\N	universal-auth
befa3221-f7cd-471b-bd3e-9ffc07bd8cf1	2592000	2592000	1	0	2025-12-04 17:20:16.42+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:20:16.286802+00	2025-12-04 17:21:10.134375+00	\N	universal-auth
635266ff-39a2-43cb-9745-9d367cb9fa1c	2592000	2592000	1	0	2025-12-04 17:20:30.273+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:20:30.157179+00	2025-12-04 17:21:26.113353+00	\N	universal-auth
3bb0077b-dbf1-401d-b6e8-52fad644ce2b	2592000	2592000	1	0	2025-12-04 17:23:11.493+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:23:11.394118+00	2025-12-04 17:24:19.007049+00	\N	universal-auth
e133eb06-0ea6-4780-bf54-31d630c6c330	2592000	2592000	1	0	2025-12-04 17:23:52.94+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:23:52.812979+00	2025-12-04 17:24:49.767577+00	\N	universal-auth
fb87c7b6-1529-4755-a781-27b89ee7bb08	2592000	2592000	1	0	2025-12-04 17:30:41.784+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:30:41.680955+00	2025-12-04 17:31:43.628715+00	\N	universal-auth
7fa739d8-0649-4eb6-b39d-48bdcd1f613d	2592000	2592000	1	0	2025-12-04 17:30:57.668+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:30:57.564726+00	2025-12-04 17:31:55.291095+00	\N	universal-auth
6338c2ed-ae95-4f4d-add3-a318cbfc3752	2592000	2592000	1	0	2025-12-04 17:32:59.343+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:32:59.227459+00	2025-12-04 17:34:02.350758+00	\N	universal-auth
41c3230d-0a70-4336-aeeb-ffdd0feab5de	2592000	2592000	1	0	2025-12-04 17:40:06.376+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:40:06.283687+00	2025-12-04 17:41:03.401339+00	\N	universal-auth
4c6ab734-3628-4b56-b9d4-8c4717575a89	2592000	2592000	1	0	2025-12-04 17:40:30.488+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:40:30.3888+00	2025-12-04 17:41:22.704315+00	\N	universal-auth
e4c6fb5b-a827-4552-8012-9651dc923911	2592000	2592000	1	0	2025-12-04 17:40:44.896+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:40:44.776799+00	2025-12-04 17:41:36.383993+00	\N	universal-auth
51697c1c-b810-47c1-90fb-4ec17c0ee51e	2592000	2592000	1	0	2025-12-04 17:42:51.122+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:42:50.968984+00	2025-12-04 17:43:49.212364+00	\N	universal-auth
916a229f-2b9c-4862-a63a-369e1106704a	2592000	2592000	1	0	2025-12-04 17:44:31.247+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:44:31.146543+00	2025-12-04 17:45:39.737489+00	\N	universal-auth
7dcd6d96-1406-433c-9042-1b9a3bdeee8f	2592000	2592000	1	0	2025-12-04 17:49:12.475+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:49:12.352149+00	2025-12-04 17:50:06.621608+00	\N	universal-auth
2b298cca-46e3-4e22-aee2-ff2a19cde852	2592000	2592000	1	0	2025-12-04 17:51:10.631+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:51:10.510614+00	2025-12-04 17:52:10.867063+00	\N	universal-auth
114f4aa5-f648-4529-a44f-989ce5638a90	2592000	2592000	1	0	2025-12-04 17:51:53.635+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:51:53.501584+00	2025-12-04 17:53:03.436669+00	\N	universal-auth
f069cac4-f056-4b1b-878a-d1fd566542db	2592000	2592000	1	0	2025-12-04 17:52:12.04+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:52:11.937298+00	2025-12-04 17:53:21.436009+00	\N	universal-auth
1229eb86-0530-4250-a241-2e797e239d9a	2592000	2592000	1	0	2025-12-04 17:52:51.667+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:52:51.559982+00	2025-12-04 17:53:45.464888+00	\N	universal-auth
64212fbf-3855-4e2b-ac30-19b068a923db	2592000	2592000	1	0	2025-12-04 17:52:59.32+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:52:59.221826+00	2025-12-04 17:53:51.99793+00	\N	universal-auth
11eeb476-154a-42ba-8726-3215ea295e56	2592000	2592000	1	0	2025-12-04 17:53:54.752+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:53:54.6509+00	2025-12-04 17:54:55.543907+00	\N	universal-auth
beb19b25-7eb1-47c4-afa7-0bc554826e0d	2592000	2592000	1	0	2025-12-04 17:54:20.724+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:54:20.556071+00	2025-12-04 17:55:11.431257+00	\N	universal-auth
e51a104f-3f8e-4cb1-8261-f949b3a17177	2592000	2592000	1	0	2025-12-04 17:54:31.804+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:54:31.702367+00	2025-12-04 17:55:25.006651+00	\N	universal-auth
bd217ed4-87fc-46a0-b5f4-8f43e85c5e88	2592000	2592000	1	0	2025-12-04 17:55:38.028+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:55:37.901941+00	2025-12-04 17:56:36.075191+00	\N	universal-auth
c423ad18-4969-47d3-97ae-271c8eae0559	2592000	2592000	1	0	2025-12-04 17:55:59.724+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:55:59.571911+00	2025-12-04 17:57:05.42987+00	\N	universal-auth
1035a816-99ea-459f-9057-bc9402819bc5	2592000	2592000	1	0	2025-12-04 17:58:02.736+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:58:02.623488+00	2025-12-04 17:59:02.969565+00	\N	universal-auth
45648c3b-9901-477f-ad04-e4c782f07497	2592000	2592000	1	0	2025-12-04 17:58:56.438+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:58:56.022851+00	2025-12-04 17:59:51.116558+00	\N	universal-auth
e5377431-6b63-4f0f-ba7c-54ad50b82b54	2592000	2592000	1	0	2025-12-04 17:58:57.501+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:58:57.380816+00	2025-12-04 18:00:05.290689+00	\N	universal-auth
eae0a806-8ef3-4a23-9119-8e3128f342e1	2592000	2592000	126430	0	2025-12-23 19:07:20.703+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-08 19:09:16.355131+00	2025-12-23 19:07:22.956978+00	\N	kubernetes-auth
db2e0883-e2f1-421f-9f9d-9ff371365876	2592000	2592000	1	0	2025-12-02 19:13:09.448+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-02 19:13:09.23477+00	2025-12-02 19:14:04.964038+00	\N	universal-auth
8ba3078f-b6ef-4a04-8876-99d01b89abef	2592000	2592000	1	0	2025-12-04 17:20:41.933+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:20:41.823545+00	2025-12-04 17:21:49.729414+00	\N	universal-auth
7f7ca3b7-b0cb-4c81-b2b3-c3739fe4bea2	2592000	2592000	1	0	2025-12-04 17:24:01.779+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:24:01.674251+00	2025-12-04 17:25:03.731303+00	\N	universal-auth
2b9d6e34-2b79-4638-9198-6bd79f064c3d	2592000	2592000	1	0	2025-12-04 17:24:10.304+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:24:10.159548+00	2025-12-04 17:25:16.002836+00	\N	universal-auth
357544ef-0115-494f-afab-655438063897	2592000	2592000	1	0	2025-12-04 17:25:03.162+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:25:03.038696+00	2025-12-04 17:25:57.020034+00	\N	universal-auth
d1b18071-f41b-46f4-ba26-4b18ca1d9d7a	2592000	2592000	1	0	2025-12-04 17:27:32.406+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:27:32.303909+00	2025-12-04 17:28:30.531106+00	\N	universal-auth
26ff5d23-fbd0-46cd-a83e-02227045fdff	2592000	2592000	1	0	2025-12-04 17:30:50.975+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:30:50.890023+00	2025-12-04 17:31:56.899285+00	\N	universal-auth
cf1e9f45-88ec-405b-9c07-583d1590342d	2592000	2592000	1	0	2025-12-04 17:38:30.844+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:38:30.734333+00	2025-12-04 17:39:30.232511+00	\N	universal-auth
672b255b-25bd-4bcb-8729-b1dd0f00a283	2592000	2592000	1	0	2025-12-04 17:42:33.787+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:42:33.712246+00	2025-12-04 17:43:31.375532+00	\N	universal-auth
f8c1e5aa-c322-4092-8638-15bf9d00003e	2592000	2592000	1	0	2025-12-04 17:42:42.428+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:42:42.325479+00	2025-12-04 17:43:50.466115+00	\N	universal-auth
48975771-3420-404a-8568-371d77fd0ec8	2592000	2592000	1	0	2025-12-04 17:42:59.401+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:42:59.306817+00	2025-12-04 17:44:07.354111+00	\N	universal-auth
bce977d3-f1b4-45ff-9319-c7b036113417	2592000	2592000	1	0	2025-12-04 17:44:39.831+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:44:39.725279+00	2025-12-04 17:45:49.684579+00	\N	universal-auth
2e9acc96-7ce8-4d19-a88f-30a9e5bf64cb	2592000	2592000	1	0	2025-12-04 17:51:21.629+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:51:21.48941+00	2025-12-04 17:52:25.9432+00	\N	universal-auth
48acd813-f6cb-4c5d-896a-9628e2c1bdb2	2592000	2592000	1	0	2025-12-04 17:53:07.648+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:53:07.562643+00	2025-12-04 17:54:02.255633+00	\N	universal-auth
148f0265-399a-42f9-b354-cc642e533af9	2592000	2592000	1	0	2025-12-04 17:53:29.699+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:53:29.593727+00	2025-12-04 17:54:23.366659+00	\N	universal-auth
885f5ce9-2b04-4cbb-8334-92e74d97e892	2592000	2592000	1	0	2025-12-04 17:53:40.502+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:53:40.39532+00	2025-12-04 17:54:48.000267+00	\N	universal-auth
e0325289-d5f5-4886-9c72-4ad6738937e6	2592000	2592000	1	0	2025-12-04 17:55:48.37+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:55:48.282336+00	2025-12-04 17:56:40.096548+00	\N	universal-auth
c8b54b83-fc1e-4eb3-8880-0ae4600b764f	2592000	2592000	1	0	2025-12-04 17:58:11.793+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:58:11.690902+00	2025-12-04 17:59:10.20693+00	\N	universal-auth
1343a210-e3be-41e9-ba3b-919edf2eb7ca	2592000	2592000	1	0	2025-12-04 17:58:32.133+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:58:32.01036+00	2025-12-04 17:59:39.757099+00	\N	universal-auth
0d05347d-0e3c-431b-a98e-c3717f616e33	2592000	2592000	1	0	2025-12-04 17:59:24.887+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 17:59:24.71911+00	2025-12-04 18:00:24.77084+00	\N	universal-auth
2665d12d-e2c3-4c85-abd2-1a79788ad174	2592000	2592000	1	0	2025-12-04 18:00:07.426+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 18:00:07.196013+00	2025-12-04 18:01:01.285229+00	\N	universal-auth
926207b1-8ea7-4d6c-b7c7-519e3d20191b	2592000	2592000	109968	0	2025-12-23 19:07:09.696+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 17:23:09.958003+00	2025-12-23 19:07:19.734462+00	\N	kubernetes-auth
e751696e-447a-4cea-8d4b-790565e2d6d9	2592000	2592000	1	0	2025-12-04 18:00:10.451+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 18:00:10.246529+00	2025-12-04 18:01:09.522757+00	\N	universal-auth
74c37c47-d9c0-495a-b7af-db0cd1cd034f	2592000	2592000	1	0	2025-12-03 18:34:57.711+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:34:57.495147+00	2025-12-03 18:36:05.425248+00	\N	universal-auth
9a5a6585-fc69-468d-bf07-331d60f4aa6f	2592000	2592000	1	0	2025-12-03 18:35:14.219+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:35:14.060525+00	2025-12-03 18:36:10.250856+00	\N	universal-auth
5f614e1c-ed9b-4129-a444-90ccde4a746e	2592000	2592000	1	0	2025-12-03 18:37:18.331+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:37:18.224564+00	2025-12-03 18:38:22.235139+00	\N	universal-auth
5620978c-0979-4b22-b352-095572d740bf	2592000	2592000	1	0	2025-12-03 18:40:33.173+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:40:33.069216+00	2025-12-03 18:41:40.14314+00	\N	universal-auth
3db847e0-7e55-47bc-a212-382d84a45f88	2592000	2592000	1	0	2025-12-03 18:41:01.665+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:41:01.568901+00	2025-12-03 18:42:00.850215+00	\N	universal-auth
14ac73f4-6f21-4e13-89ee-81a7396fb5a5	2592000	2592000	1	0	2025-12-03 18:41:14.955+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:41:14.799419+00	2025-12-03 18:42:22.462703+00	\N	universal-auth
da4a41e8-300f-427d-a9a3-2d93220705cc	2592000	2592000	1	0	2025-12-03 18:43:22.113+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:43:21.997022+00	2025-12-03 18:44:17.770804+00	\N	universal-auth
cbc8308e-a669-4317-956a-40d72e57fcfd	2592000	2592000	1	0	2025-12-03 18:43:39.998+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:43:39.904551+00	2025-12-03 18:44:34.353081+00	\N	universal-auth
4ace17e6-a471-4213-a5e9-8adb19feccaf	2592000	2592000	1	0	2025-12-03 18:44:01.114+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:44:00.99156+00	2025-12-03 18:44:57.671754+00	\N	universal-auth
1c8d294a-eb56-4e8b-8806-16fe191ee0a4	2592000	2592000	1	0	2025-12-03 18:45:16.836+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:45:16.560615+00	2025-12-03 18:46:26.121454+00	\N	universal-auth
e7056325-b3dd-4e96-9e46-ddde0d70a746	2592000	2592000	1	0	2025-12-03 18:46:00.483+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:46:00.392468+00	2025-12-03 18:46:51.253084+00	\N	universal-auth
89cd0c41-0091-4095-8881-065034e6a3e7	2592000	2592000	1	0	2025-12-03 18:46:16.72+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:46:16.619805+00	2025-12-03 18:47:26.231283+00	\N	universal-auth
d0de03db-46bb-43f4-a491-2513d5eaa4d9	2592000	2592000	1	0	2025-12-03 18:46:25.193+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:46:25.070875+00	2025-12-03 18:47:27.135422+00	\N	universal-auth
055c50ae-9846-41da-bd4d-328fccea4f65	2592000	2592000	1	0	2025-12-03 18:46:45.837+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:46:45.667374+00	2025-12-03 18:47:41.912128+00	\N	universal-auth
29b13e26-60a8-465b-984e-70b3fa340470	2592000	2592000	1	0	2025-12-03 18:46:59.662+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:46:59.411508+00	2025-12-03 18:47:57.796017+00	\N	universal-auth
144e34ab-aaa1-4924-b2b6-014ea5c6d4a8	2592000	2592000	1	0	2025-12-03 18:52:01.167+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:52:01.020856+00	2025-12-03 18:53:00.510009+00	\N	universal-auth
658b572d-57b1-4240-9f43-8ef0f635132e	2592000	2592000	1	0	2025-12-03 18:52:21.747+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:52:21.607811+00	2025-12-03 18:53:29.007681+00	\N	universal-auth
7cca54ae-259f-4d0a-a193-e9d24e260338	2592000	2592000	1	0	2025-12-03 18:53:41.499+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:53:41.383261+00	2025-12-03 18:54:37.568806+00	\N	universal-auth
652789ec-1d7c-42f6-83aa-4008fa7e214f	2592000	2592000	1	0	2025-12-03 18:54:01.562+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:54:01.429815+00	2025-12-03 18:55:05.213143+00	\N	universal-auth
51824cc3-be99-46a8-8bea-acf8ae985ec4	2592000	2592000	1	0	2025-12-03 18:54:09.874+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:54:09.763007+00	2025-12-03 18:55:10.946093+00	\N	universal-auth
0843b127-0a43-475b-ac9c-299a0547c72c	2592000	2592000	1	0	2025-12-03 19:28:06.604+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:28:06.500037+00	2025-12-03 19:29:06.16753+00	\N	universal-auth
7717928d-02a6-4b04-b325-b5a68fef5a02	2592000	2592000	1	0	2025-12-03 19:29:09.741+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:29:09.629135+00	2025-12-03 19:30:10.693678+00	\N	universal-auth
f711bec1-a9f4-42f7-8144-421132e8c9c3	2592000	2592000	1	0	2025-12-03 19:29:27.661+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:29:27.519929+00	2025-12-03 19:30:18.540336+00	\N	universal-auth
4fd2030c-9ce3-4f38-a75f-53efda38c5d4	2592000	2592000	1	0	2025-12-04 18:03:38.784+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 18:03:38.601554+00	2025-12-04 18:04:48.28625+00	\N	universal-auth
9da0112c-b5d2-4bdc-8fae-7df9ead13a47	2592000	2592000	528	0	2025-12-10 18:59:05.352+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 17:30:17.774402+00	2025-12-10 18:59:21.123604+00	\N	kubernetes-auth
20941752-9ccf-410a-a10e-2f857fa05ee4	2592000	2592000	1	0	2025-12-03 18:37:07.223+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:37:07.132774+00	2025-12-03 18:37:58.314227+00	\N	universal-auth
ef1ceb0a-9491-4e11-82ff-8ddd027ee44a	2592000	2592000	1	0	2025-12-03 18:38:08.273+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:38:08.165112+00	2025-12-03 18:39:17.110253+00	\N	universal-auth
11da0ad0-5b1c-4821-a447-b11bd1a11dc3	2592000	2592000	1	0	2025-12-03 18:38:23.06+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:38:22.934826+00	2025-12-03 18:39:32.588633+00	\N	universal-auth
3063786e-3710-49b6-9852-4d1a547018d6	2592000	2592000	1	0	2025-12-03 18:40:49.812+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:40:49.723236+00	2025-12-03 18:41:51.402685+00	\N	universal-auth
71a21a53-d5de-4fbe-99fa-9091ec38b8f8	2592000	2592000	1	0	2025-12-03 18:41:27.157+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:41:27.027076+00	2025-12-03 18:42:27.988885+00	\N	universal-auth
9a124d85-6da4-4c97-9c2b-1d1023b07a01	2592000	2592000	1	0	2025-12-03 18:42:31.156+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:42:31.033064+00	2025-12-03 18:43:23.883334+00	\N	universal-auth
8e2b4d72-efda-44a5-b621-659475bc47ab	2592000	2592000	1	0	2025-12-03 18:43:31.929+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:43:31.799578+00	2025-12-03 18:44:41.893149+00	\N	universal-auth
e208debe-85cd-4e48-a5c3-916587f3968f	2592000	2592000	1	0	2025-12-03 18:46:34.385+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:46:34.294282+00	2025-12-03 18:47:24.633451+00	\N	universal-auth
bc55cf41-ad2f-4963-9260-dbc8ea6cd0c7	2592000	2592000	1	0	2025-12-04 18:10:28.631+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 18:10:28.541289+00	2025-12-04 18:11:35.899443+00	\N	universal-auth
2c4d529d-a772-452e-8301-befdacd998ce	2592000	2592000	1	0	2025-12-04 18:11:02.556+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 18:11:02.461129+00	2025-12-04 18:12:07.863482+00	\N	universal-auth
8f449c3a-5fdf-4e2d-9d48-c8c9544d3610	2592000	2592000	1	0	2025-12-04 20:00:40.104+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:00:40.00152+00	2025-12-04 20:01:44.437775+00	\N	universal-auth
6fcfc778-2c2b-4db7-8283-72c28c4480b6	2592000	2592000	1	0	2025-12-04 20:02:01.664+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:02:01.52928+00	2025-12-04 20:02:57.43885+00	\N	universal-auth
d30d37c0-9004-443c-b82d-6a31ae9e78af	2592000	2592000	1	0	2025-12-04 20:02:19.319+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:02:19.21629+00	2025-12-04 20:03:24.180768+00	\N	universal-auth
2ebb96b6-cf79-4de0-9f92-afb5c43e49db	2592000	2592000	1	0	2025-12-04 20:04:24.215+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:04:24.053998+00	2025-12-04 20:05:25.213007+00	\N	universal-auth
1fc6fecd-756f-4ada-8cd9-fd8ab733cb0d	2592000	2592000	1	0	2025-12-04 20:05:23.883+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:05:23.797339+00	2025-12-04 20:06:29.659427+00	\N	universal-auth
3ced75f0-1327-485a-a1a0-1809ec45c41c	2592000	2592000	35	0	2025-12-10 18:18:42.495+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 18:12:58.775889+00	2025-12-10 18:19:10.619354+00	\N	kubernetes-auth
c5b7eae2-11d1-4989-9d50-60f9b530357b	2592000	2592000	98	0	2025-12-10 18:35:03.23+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 18:18:43.072576+00	2025-12-10 18:36:08.391135+00	\N	kubernetes-auth
63ee8b3b-2c0c-46ff-97a2-7a29710849b7	2592000	2592000	109548	0	2025-12-23 19:07:40.066+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 18:35:03.505856+00	2025-12-23 19:07:43.269283+00	\N	kubernetes-auth
2791dcd5-05af-465b-9180-2f6408a41c35	2592000	2592000	1	0	2025-12-03 18:53:34.766+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:53:34.672763+00	2025-12-03 18:54:27.618453+00	\N	universal-auth
0a4a98ce-7bf5-447f-be2c-b6558b85848d	2592000	2592000	1	0	2025-12-03 18:55:21.769+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:55:21.637672+00	2025-12-03 18:56:23.522008+00	\N	universal-auth
6fccc4cc-96d4-4696-b1a0-d4f50da118cf	2592000	2592000	1	0	2025-12-03 18:55:38.449+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 18:55:38.306234+00	2025-12-03 18:56:47.138027+00	\N	universal-auth
f8cdfd8f-82ee-4416-985e-d009f6a4ec85	2592000	2592000	1	0	2025-12-03 19:27:57.913+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:27:57.794925+00	2025-12-03 19:29:00.437276+00	\N	universal-auth
e114a4f8-18c8-4c33-b8e9-1cc9cdfd5f41	2592000	2592000	1	0	2025-12-03 19:29:01.399+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:29:01.28083+00	2025-12-03 19:29:55.014691+00	\N	universal-auth
591ce546-a5df-4d58-b465-9d920045ede7	2592000	2592000	1	0	2025-12-03 19:29:18.838+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:29:18.747703+00	2025-12-03 19:30:13.51308+00	\N	universal-auth
f8c837be-d06b-43c5-ad34-02cc95c717ec	2592000	2592000	1	0	2025-12-03 19:29:38.67+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:29:38.539827+00	2025-12-03 19:30:44.675599+00	\N	universal-auth
5c6de6da-89d5-43ba-b8c9-606afbefb96f	2592000	2592000	1	0	2025-12-03 19:29:55.949+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:29:55.849202+00	2025-12-03 19:31:04.887492+00	\N	universal-auth
4e5acce8-bd65-4715-ad32-1780f00a3202	2592000	2592000	1	0	2025-12-04 18:10:55.628+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 18:10:55.529796+00	2025-12-04 18:11:58.617362+00	\N	universal-auth
d754399d-3d5a-4176-b938-3aa13872e3c8	2592000	2592000	1	0	2025-12-04 20:00:09.312+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:00:09.190273+00	2025-12-04 20:01:04.733211+00	\N	universal-auth
12ee75f4-b599-4a7a-8230-3a8b62688225	2592000	2592000	1	0	2025-12-04 20:00:33.838+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:00:33.747739+00	2025-12-04 20:01:32.883391+00	\N	universal-auth
7207fe2a-1977-4794-889e-23f467e4ddd6	2592000	2592000	1	0	2025-12-04 20:02:08.137+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:02:07.83793+00	2025-12-04 20:03:03.671363+00	\N	universal-auth
cfe3eef9-d8ee-4559-8b88-0c50bb0ef581	2592000	2592000	1	0	2025-12-04 20:02:13.591+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:02:13.495426+00	2025-12-04 20:03:05.883+00	\N	universal-auth
54a92b1f-b638-4d51-8a18-7c81aa349a30	2592000	2592000	1	0	2025-12-04 20:03:52.269+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:03:52.179603+00	2025-12-04 20:04:58.067646+00	\N	universal-auth
7431949d-83bb-4f87-958a-c370a98e5766	2592000	2592000	1	0	2025-12-04 20:04:34.304+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:04:34.214022+00	2025-12-04 20:05:30.84474+00	\N	universal-auth
4f822aba-8102-4076-aa6e-93ba3da366d0	2592000	2592000	1	0	2025-12-04 20:05:16.923+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:05:16.831933+00	2025-12-04 20:06:09.349453+00	\N	universal-auth
85e63080-2414-441e-8954-d7a8ad9b6fd2	2592000	2592000	1	0	2025-12-04 20:05:30.436+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 20:05:30.323107+00	2025-12-04 20:06:35.187187+00	\N	universal-auth
065ad7e4-756e-48dd-876c-eddeba0940da	2592000	2592000	352	0	2025-12-10 19:58:14.917+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 18:59:06.504272+00	2025-12-10 19:58:59.263761+00	\N	kubernetes-auth
0c03660d-4629-4bff-b474-3d6a801458ec	2592000	2592000	1	0	2025-12-03 19:31:05.872+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:31:05.676003+00	2025-12-03 19:32:15.054927+00	\N	universal-auth
fbbd74a6-656b-43f1-a9fb-1b00c303e154	2592000	2592000	1	0	2025-12-03 19:31:16.886+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:31:16.783654+00	2025-12-03 19:32:17.565198+00	\N	universal-auth
df0ec282-824b-4fd1-964e-c37850f07da0	2592000	2592000	1	0	2025-12-03 19:38:24.999+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:38:24.878061+00	2025-12-03 19:39:28.21848+00	\N	universal-auth
52219846-ee2e-4ba2-8bab-23151db190a5	2592000	2592000	1	0	2025-12-03 19:38:43.963+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:38:43.874901+00	2025-12-03 19:39:37.867319+00	\N	universal-auth
1be407be-78b2-4502-bad7-44aba1fccc40	2592000	2592000	1	0	2025-12-03 19:41:30.972+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:41:30.774581+00	2025-12-03 19:42:25.445792+00	\N	universal-auth
d735924b-8bf5-411b-81d4-632784050878	2592000	2592000	1	0	2025-12-03 19:41:47.461+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:41:47.354525+00	2025-12-03 19:42:42.838712+00	\N	universal-auth
e96675f7-c1a2-4253-a1fd-d3a8a5ed6ef0	2592000	2592000	1	0	2025-12-03 19:42:13.08+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:42:12.93457+00	2025-12-03 19:43:20.231735+00	\N	universal-auth
a954bf07-8ac6-4427-a0e6-f59c310027e1	2592000	2592000	1	0	2025-12-03 19:43:32.432+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:43:32.298045+00	2025-12-03 19:44:27.989037+00	\N	universal-auth
62a2a9e9-a96b-4394-a216-c4f5e0bbe1ae	2592000	2592000	1	0	2025-12-03 19:43:54.246+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:43:54.106097+00	2025-12-03 19:45:02.673345+00	\N	universal-auth
ac26d3f9-7cfd-4c41-9f54-c61974b0747b	2592000	2592000	1	0	2025-12-03 19:44:11.511+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:44:11.411724+00	2025-12-03 19:45:19.535238+00	\N	universal-auth
4856567c-af05-4e3a-9c21-99e956bb1feb	2592000	2592000	1	0	2025-12-03 19:44:29.349+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:44:29.236108+00	2025-12-03 19:45:21.968193+00	\N	universal-auth
de9c84f8-1388-410b-9da3-986837bea295	2592000	2592000	1	0	2025-12-03 19:44:48.186+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:44:48.040049+00	2025-12-03 19:45:39.259436+00	\N	universal-auth
f9b1d0a8-7e50-4728-9462-347fdd6dc3f8	2592000	2592000	1	0	2025-12-03 19:45:09.626+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:45:09.497127+00	2025-12-03 19:46:00.175092+00	\N	universal-auth
476f85d8-07cb-49ef-b3fa-85dfcf8a1131	2592000	2592000	1	0	2025-12-03 19:45:29.045+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:45:28.878034+00	2025-12-03 19:46:35.775399+00	\N	universal-auth
a83339d8-7f46-4d39-8d43-d09e9e4bf740	2592000	2592000	1	0	2025-12-03 19:45:47.887+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:45:47.771626+00	2025-12-03 19:46:52.252622+00	\N	universal-auth
4b3d02e4-031d-4eca-ab36-3421649bd8dc	2592000	2592000	1	0	2025-12-03 19:46:15.384+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:46:15.277518+00	2025-12-03 19:47:22.91268+00	\N	universal-auth
0c5ed4ca-3d51-4b7b-8582-64cf363e5126	2592000	2592000	1	0	2025-12-03 19:46:31.149+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:46:30.878883+00	2025-12-03 19:47:33.867692+00	\N	universal-auth
00464849-a835-4db7-87e0-912eaa8b7421	2592000	2592000	1	0	2025-12-03 19:46:50.13+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:46:49.998593+00	2025-12-03 19:47:52.461858+00	\N	universal-auth
f9737cb0-68f8-48f2-87be-c23f2a00ec29	2592000	2592000	1	0	2025-12-03 19:51:55.74+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:51:55.591084+00	2025-12-03 19:53:02.162997+00	\N	universal-auth
62440326-4b30-409a-9435-7463eb3f70dc	2592000	2592000	1	0	2025-12-03 19:52:18.288+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:52:18.139946+00	2025-12-03 19:53:10.905393+00	\N	universal-auth
29ea5ed4-6a93-4370-81ce-66a85822b2c5	2592000	2592000	1	0	2025-12-03 20:00:04.861+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:00:04.708499+00	2025-12-03 20:01:02.348862+00	\N	universal-auth
be2d3316-1555-46a2-a815-cf3429591608	2592000	2592000	1	0	2025-12-03 20:01:02.11+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:01:01.959353+00	2025-12-03 20:02:07.080696+00	\N	universal-auth
b870d7a0-23e8-49f4-af22-9621e7264149	2592000	2592000	1	0	2025-12-03 20:05:39.559+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:05:39.44798+00	2025-12-03 20:06:42.722274+00	\N	universal-auth
4b87643a-2cf8-43eb-814e-a9168265916b	2592000	2592000	1	0	2025-12-03 20:10:46.622+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:10:46.39497+00	2025-12-03 20:11:41.053408+00	\N	universal-auth
f4173b36-3f6f-47fc-b549-bb4a69bb91e8	2592000	2592000	1	0	2025-12-03 20:12:10.982+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:12:10.866956+00	2025-12-03 20:13:02.889214+00	\N	universal-auth
18ecc8dc-da71-4e24-a200-dd7745530ac7	2592000	2592000	1	0	2025-12-03 20:19:13.486+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:19:13.348316+00	2025-12-03 20:20:23.27445+00	\N	universal-auth
20374815-d6dd-4589-81f0-2c08bf28b923	2592000	2592000	1	0	2025-12-03 20:19:32.832+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:19:32.64835+00	2025-12-03 20:20:37.853079+00	\N	universal-auth
0a6bd0de-3778-4fad-8f1c-59d7b36214aa	2592000	2592000	1	0	2025-12-03 20:20:16.823+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:20:16.668423+00	2025-12-03 20:21:25.698348+00	\N	universal-auth
3f94f310-5f76-49f8-9faa-20c8a010962c	2592000	2592000	1	0	2025-12-03 20:21:14.76+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:21:14.642759+00	2025-12-03 20:22:17.861321+00	\N	universal-auth
55748968-1263-436c-b0c3-b655529a530e	2592000	2592000	1	0	2025-12-04 22:16:24.95+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:16:24.85556+00	2025-12-04 22:17:32.7681+00	\N	universal-auth
7205cf4f-5d4a-4a33-ba31-0be2034ac372	2592000	2592000	1	0	2025-12-04 22:16:41.417+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:16:41.327938+00	2025-12-04 22:17:34.877932+00	\N	universal-auth
819263d1-ebb9-49c0-97eb-56509db496f5	2592000	2592000	1	0	2025-12-04 22:17:01.688+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:17:01.601905+00	2025-12-04 22:17:54.180367+00	\N	universal-auth
17735d6a-c154-4555-b1f4-7c1774519ec4	2592000	2592000	1	0	2025-12-04 22:17:45.805+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:17:45.708628+00	2025-12-04 22:18:49.465937+00	\N	universal-auth
72285298-271b-404f-b8f1-80ac2b91dc11	2592000	2592000	1	0	2025-12-04 22:19:06.807+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:19:06.722637+00	2025-12-04 22:20:04.747364+00	\N	universal-auth
a04c97ab-ada9-4b6a-aff3-81ba2b6da140	2592000	2592000	1	0	2025-12-04 22:19:22.813+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:19:22.724307+00	2025-12-04 22:20:14.623329+00	\N	universal-auth
5a08dd93-97df-402f-92da-48300e7bc967	2592000	2592000	1	0	2025-12-04 22:20:04.744+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:20:04.658429+00	2025-12-04 22:20:55.337875+00	\N	universal-auth
1680c881-6dff-4e8b-a65f-f8bb9c78cdc4	2592000	2592000	1	0	2025-12-04 22:23:21.458+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:23:21.301484+00	2025-12-04 22:24:22.691525+00	\N	universal-auth
cb3ff678-bbd9-4742-892f-dd370831cc90	2592000	2592000	1	0	2025-12-03 19:38:14.905+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:38:14.791481+00	2025-12-03 19:39:07.009367+00	\N	universal-auth
7ea45fff-12c0-4872-a356-b869e19cde04	2592000	2592000	1	0	2025-12-03 19:38:34.69+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:38:34.57694+00	2025-12-03 19:39:39.977112+00	\N	universal-auth
f4591741-57d2-42ac-9e84-dcd6ece6c1da	2592000	2592000	1	0	2025-12-03 19:41:38.494+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:41:38.38363+00	2025-12-03 19:42:47.864471+00	\N	universal-auth
851e685f-d744-446a-a4a8-559efbdd660c	2592000	2592000	1	0	2025-12-03 19:41:57.546+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:41:57.430181+00	2025-12-03 19:43:03.443973+00	\N	universal-auth
bdedb0f3-b287-4112-9c6c-3af94a6b7ee8	2592000	2592000	1	0	2025-12-03 19:42:21.685+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:42:21.586328+00	2025-12-03 19:43:26.461379+00	\N	universal-auth
c5d8d3e9-3cbe-4adf-8d4a-b127630e21d4	2592000	2592000	1	0	2025-12-03 19:44:02.538+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:44:02.388792+00	2025-12-03 19:44:59.536284+00	\N	universal-auth
37700cd9-198e-4d27-9329-60946cd5e7c3	2592000	2592000	1	0	2025-12-03 19:44:19.746+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:44:19.630122+00	2025-12-03 19:45:22.17376+00	\N	universal-auth
f1ca34b4-10c0-4de5-9390-81d1afb3a335	2592000	2592000	1	0	2025-12-03 19:44:55.53+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:44:55.438994+00	2025-12-03 19:45:54.645842+00	\N	universal-auth
3b2c56f9-c485-4417-b14e-e6704a77e06c	2592000	2592000	1	0	2025-12-04 22:16:51.652+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:16:51.562692+00	2025-12-04 22:17:49.95505+00	\N	universal-auth
1bf71fc6-015d-4157-912b-b350bec4af07	2592000	2592000	1	0	2025-12-04 22:17:34.514+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:17:34.42497+00	2025-12-04 22:18:42.835331+00	\N	universal-auth
787b75b6-ae48-4ff7-9006-101758b0a32c	2592000	2592000	1	0	2025-12-04 22:19:38.389+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:19:38.315699+00	2025-12-04 22:20:32.319655+00	\N	universal-auth
09ea66eb-d126-4fbb-bf20-9ec8fe081405	2592000	2592000	109053	0	2025-12-23 19:07:30.794+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 19:58:25.1327+00	2025-12-23 19:07:36.530778+00	\N	kubernetes-auth
1dab5aa2-d049-499f-91a3-07e2b17bf224	2592000	2592000	1	0	2025-12-03 19:45:37.402+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:45:37.306845+00	2025-12-03 19:46:27.721896+00	\N	universal-auth
d44aabab-b000-4b0c-804e-5c1b499f3b50	2592000	2592000	1	0	2025-12-03 19:45:55.884+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:45:55.733429+00	2025-12-03 19:46:51.247302+00	\N	universal-auth
5064afa5-fa71-42b8-8848-5314db75555b	2592000	2592000	1	0	2025-12-03 19:46:05.109+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:46:04.998678+00	2025-12-03 19:46:57.378632+00	\N	universal-auth
9e4e8fdf-7a83-4148-978f-b841e5fc694e	2592000	2592000	1	0	2025-12-03 19:46:41.212+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:46:41.113349+00	2025-12-03 19:47:48.54558+00	\N	universal-auth
c1751677-c25b-4cc5-84e5-ba622fb8cd4c	2592000	2592000	1	0	2025-12-03 19:47:22.298+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:47:22.185539+00	2025-12-03 19:48:30.865385+00	\N	universal-auth
286f476b-4ea2-410c-9aa0-1c1039accb90	2592000	2592000	1	0	2025-12-03 19:47:41.585+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:47:41.405041+00	2025-12-03 19:48:39.810531+00	\N	universal-auth
317d8bd5-d10c-43a5-a21e-7b40b69220dd	2592000	2592000	1	0	2025-12-03 19:59:12.155+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 19:59:12.04171+00	2025-12-03 20:00:20.537475+00	\N	universal-auth
5b31ce0c-ec78-4485-acdc-19321ed48211	2592000	2592000	1	0	2025-12-03 20:00:13.411+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:00:13.299753+00	2025-12-03 20:01:23.060101+00	\N	universal-auth
4b214930-d01b-42bd-a32b-cbab4e0a185e	2592000	2592000	1	0	2025-12-03 20:01:14.062+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:01:13.956773+00	2025-12-03 20:02:14.926526+00	\N	universal-auth
6fb9425c-f792-417b-9496-e16f0043a052	2592000	2592000	1	0	2025-12-03 20:06:11.301+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:06:11.164749+00	2025-12-03 20:07:08.849603+00	\N	universal-auth
df81ebbf-3069-4895-9fe6-cb6fc8ca8747	2592000	2592000	1	0	2025-12-03 20:10:33.084+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:10:33.000267+00	2025-12-03 20:11:24.972905+00	\N	universal-auth
8c56b430-470e-4c0a-b2ac-4e7601141060	2592000	2592000	1	0	2025-12-03 20:20:01.196+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:20:01.022828+00	2025-12-03 20:20:54.535521+00	\N	universal-auth
136ae49f-b054-45df-873b-8cf22742570c	2592000	2592000	1	0	2025-12-04 22:23:21.142+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 22:23:21.041714+00	2025-12-04 22:24:18.465609+00	\N	universal-auth
6d828c22-c8d5-414f-a69c-e7a82637a1a6	2592000	2592000	1	0	2025-12-03 20:21:35.331+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:21:35.160267+00	2025-12-03 20:22:28.517546+00	\N	universal-auth
57be0f69-5ea2-4f84-bcf8-b1c3c3bce092	2592000	2592000	151525	0	2025-12-23 19:07:10.401+00	\N	f	\N	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-05 20:37:36.649766+00	2025-12-23 19:07:11.99284+00	\N	kubernetes-auth
562084a3-3ade-4026-9ef7-bbc055ad34dc	2592000	2592000	1	0	2025-12-03 20:21:49.446+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:21:49.235474+00	2025-12-03 20:22:47.707409+00	\N	universal-auth
3d441ffd-6c9f-403b-8d09-e052e65ad803	2592000	2592000	1	0	2025-12-03 20:22:03.917+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:22:03.760124+00	2025-12-03 20:22:58.262676+00	\N	universal-auth
51a78045-a18b-4a89-9f70-624cbef37733	2592000	2592000	1	0	2025-12-03 20:23:07.09+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:23:06.885025+00	2025-12-03 20:24:05.699392+00	\N	universal-auth
7cca26c6-36ef-4cd6-ad79-9008a4b2b155	2592000	2592000	1	0	2025-12-03 20:22:32.317+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:22:32.185858+00	2025-12-03 20:23:36.157731+00	\N	universal-auth
82445d33-bb7b-48ee-830f-932068f7f25a	2592000	2592000	1	0	2025-12-03 20:22:55.796+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:22:55.560784+00	2025-12-03 20:23:55.860406+00	\N	universal-auth
4abcda39-0c52-48b1-8c87-32748db4e851	2592000	2592000	1	0	2025-12-03 20:23:20.537+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 20:23:20.359809+00	2025-12-03 20:24:18.072858+00	\N	universal-auth
2cdffd3e-191a-4a5e-8ed1-1b53fe33680b	2592000	2592000	1	0	2025-12-03 21:23:21.186+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:23:20.991975+00	2025-12-03 21:24:27.831473+00	\N	universal-auth
8222af46-3b9d-4356-b1ae-e70cb94c0676	2592000	2592000	1	0	2025-12-03 21:24:44.134+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:24:43.973537+00	2025-12-03 21:25:41.099531+00	\N	universal-auth
a9957cf2-d29e-4655-9a2f-dfc7b05933e3	2592000	2592000	1	0	2025-12-03 21:27:47.627+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:27:47.471274+00	2025-12-03 21:28:45.042822+00	\N	universal-auth
171559b1-f3ed-4483-a10c-c0ec959fe668	2592000	2592000	1	0	2025-12-03 21:29:50.408+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:29:50.310411+00	2025-12-03 21:30:40.643099+00	\N	universal-auth
b6f66d7b-ac50-4cb5-a306-2a8499b9d8ab	2592000	2592000	1	0	2025-12-03 21:32:30.961+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:32:30.828951+00	2025-12-03 21:33:32.238015+00	\N	universal-auth
42f424b7-7c8d-4f56-a7c7-b18407f997cb	2592000	2592000	1	0	2025-12-03 21:32:54.437+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:32:54.22898+00	2025-12-03 21:34:03.490911+00	\N	universal-auth
846fc179-8ae7-4a4d-a4eb-e3789d236d09	2592000	2592000	1	0	2025-12-03 21:56:59.243+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:56:59.086993+00	2025-12-03 21:57:54.468198+00	\N	universal-auth
e0393ec8-0767-4b4e-85ce-7d37cf8cbb0d	2592000	2592000	1	0	2025-12-03 21:24:57.226+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:24:57.104099+00	2025-12-03 21:25:48.240535+00	\N	universal-auth
a2ef0170-a2bf-4e7a-84fe-f4d5dd9a3f47	2592000	2592000	1	0	2025-12-03 21:25:15.438+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:25:15.30942+00	2025-12-03 21:26:17.496285+00	\N	universal-auth
7659dbb8-dc20-4b1c-8864-98aec8fb3f2a	2592000	2592000	1	0	2025-12-03 21:25:37.961+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:25:37.654498+00	2025-12-03 21:26:47.547483+00	\N	universal-auth
96f14023-12b0-495f-b6d0-05993a434ba9	2592000	2592000	1	0	2025-12-03 21:25:52.514+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:25:52.398648+00	2025-12-03 21:26:49.757123+00	\N	universal-auth
7ae86258-ffb9-4d98-b4c9-a3470e708dec	2592000	2592000	1	0	2025-12-03 21:26:13.782+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:26:13.651398+00	2025-12-03 21:27:20.013345+00	\N	universal-auth
b3dd19bc-62da-468b-9115-85dec46702b8	2592000	2592000	1	0	2025-12-03 21:31:02.241+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:31:01.933576+00	2025-12-03 21:31:59.347457+00	\N	universal-auth
43da45ab-0f3f-4111-b617-ed2031a3b7b5	2592000	2592000	1	0	2025-12-03 21:32:04.428+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:32:04.284569+00	2025-12-03 21:33:07.609352+00	\N	universal-auth
7a391f03-c045-47ef-a88d-fc8b3ad87e2b	2592000	2592000	1	0	2025-12-03 21:32:45.24+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:32:45.05024+00	2025-12-03 21:33:42.989818+00	\N	universal-auth
77fa1324-f3e6-4898-baf6-7a5f65987d5d	2592000	2592000	1	0	2025-12-03 21:54:45.129+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:54:44.641194+00	2025-12-03 21:55:43.99872+00	\N	universal-auth
2025e6f6-1d50-4218-8811-bfcd4e699d5b	2592000	2592000	1	0	2025-12-03 21:54:47.573+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:54:47.451701+00	2025-12-03 21:55:44.802388+00	\N	universal-auth
29700036-62e3-4c3c-b216-3eb35db5f979	2592000	2592000	1	0	2025-12-03 21:55:42.597+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:55:42.463963+00	2025-12-03 21:56:52.546389+00	\N	universal-auth
7e8b556d-3465-409a-bde6-4e100e17b0fa	2592000	2592000	1	0	2025-12-03 21:56:03.741+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:56:03.534746+00	2025-12-03 21:57:12.852433+00	\N	universal-auth
0b4feb8f-1f82-4346-b376-5918a1393b26	2592000	2592000	1	0	2025-12-03 21:58:47.297+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:58:47.175061+00	2025-12-03 21:59:39.2037+00	\N	universal-auth
d6e0d0d5-ba67-4e4b-8779-12d663fb1b58	2592000	2592000	1	0	2025-12-03 21:58:49.529+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 21:58:49.335029+00	2025-12-03 21:59:51.166725+00	\N	universal-auth
7c7f16c0-0028-4a1e-a609-49bbba90d529	2592000	2592000	1	0	2025-12-03 22:41:02.542+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 22:41:02.395992+00	2025-12-03 22:42:07.135879+00	\N	universal-auth
b64147c0-3cf7-4570-a868-be36afe1bf01	2592000	2592000	1	0	2025-12-03 22:41:36.879+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 22:41:36.788179+00	2025-12-03 22:42:37.793261+00	\N	universal-auth
887e6853-1442-4ae5-a3d6-b0456eb8a4f0	2592000	2592000	1	0	2025-12-03 22:44:37.581+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 22:44:37.412268+00	2025-12-03 22:45:36.513207+00	\N	universal-auth
dbc92445-8315-4447-bdc7-dcf0dbd39879	2592000	2592000	1	0	2025-12-03 22:45:54.982+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 22:45:54.763742+00	2025-12-03 22:46:51.607591+00	\N	universal-auth
8c20ab76-9c12-4a74-9b51-66b56bd67169	2592000	2592000	1	0	2025-12-03 22:44:51.513+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 22:44:51.325144+00	2025-12-03 22:45:56.216965+00	\N	universal-auth
162dd712-db30-4b25-9266-d0c49b179e54	2592000	2592000	1	0	2025-12-03 22:45:09.347+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 22:45:09.198975+00	2025-12-03 22:46:08.581585+00	\N	universal-auth
d28ed4c7-99e6-49e5-a014-017ac2ffea30	2592000	2592000	1	0	2025-12-03 22:45:55.017+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-03 22:45:54.771796+00	2025-12-03 22:46:49.49695+00	\N	universal-auth
16385ddc-7e52-4553-808f-e510fce354cd	2592000	2592000	1	0	2025-12-04 15:31:32.866+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:31:32.741002+00	2025-12-04 15:32:26.383075+00	\N	universal-auth
00bf8768-1e54-434b-b7b7-91993f68d6ca	2592000	2592000	1	0	2025-12-04 15:31:46.946+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:31:46.734391+00	2025-12-04 15:32:48.894483+00	\N	universal-auth
3c667981-9f37-4694-989a-34ee75ab5b1f	2592000	2592000	1	0	2025-12-04 15:32:08.559+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:32:08.424069+00	2025-12-04 15:33:04.471627+00	\N	universal-auth
c1b3cf21-77d2-4b6c-badd-16d11ba4d0a2	2592000	2592000	1	0	2025-12-04 15:35:31.539+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:35:31.403395+00	2025-12-04 15:36:34.057714+00	\N	universal-auth
43efc185-34ee-4ee4-94ac-908636c9a3d3	2592000	2592000	1	0	2025-12-04 15:35:48.377+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:35:48.182463+00	2025-12-04 15:36:55.877877+00	\N	universal-auth
1d68f9f6-bb68-4572-af7f-28767de3e05f	2592000	2592000	1	0	2025-12-04 15:36:16.598+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:36:16.475993+00	2025-12-04 15:37:21.813727+00	\N	universal-auth
fb4e5d11-1112-4b89-9bfb-a16fb8e21bc8	2592000	2592000	1	0	2025-12-04 15:36:34.654+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:36:34.540424+00	2025-12-04 15:37:40.508423+00	\N	universal-auth
f6140af4-342d-4f0a-88c4-300fc72686e4	2592000	2592000	1	0	2025-12-04 15:38:31.867+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:38:31.761229+00	2025-12-04 15:39:40.531933+00	\N	universal-auth
464f3ce6-f9b5-4424-87bf-0f2d5193a2b9	2592000	2592000	1	0	2025-12-04 15:39:16.513+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:39:16.375609+00	2025-12-04 15:40:16.416373+00	\N	universal-auth
6519eedb-2971-4526-b60c-ffedae039993	2592000	2592000	1	0	2025-12-04 15:43:13.781+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:43:13.647645+00	2025-12-04 15:44:17.716201+00	\N	universal-auth
9986e41f-24a1-47d1-97b5-b8c5408a50b4	2592000	2592000	1	0	2025-12-04 15:46:40.014+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:46:39.885882+00	2025-12-04 15:47:49.794007+00	\N	universal-auth
66ad1eee-83ac-411e-809e-c75d03eeb794	2592000	2592000	1	0	2025-12-04 15:49:21.001+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:49:20.899914+00	2025-12-04 15:50:19.070572+00	\N	universal-auth
eb944749-8e4e-4776-b4c4-a0edcb4a859b	2592000	2592000	1	0	2025-12-04 15:32:22.064+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:32:21.89864+00	2025-12-04 15:33:13.91443+00	\N	universal-auth
2b409e57-bead-4d9e-a29a-c73ffc09d922	2592000	2592000	1	0	2025-12-04 15:32:40.273+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:32:40.162981+00	2025-12-04 15:33:44.067661+00	\N	universal-auth
2c54c83f-bdef-4a15-8779-6c49cc873a04	2592000	2592000	1	0	2025-12-04 15:35:06.975+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:35:06.848309+00	2025-12-04 15:36:01.386636+00	\N	universal-auth
ca36e121-1288-4c1d-9423-66532742e9f4	2592000	2592000	1	0	2025-12-04 15:36:03.01+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:36:02.850748+00	2025-12-04 15:37:05.023431+00	\N	universal-auth
008245bd-02fe-41ca-84f3-a540698f3749	2592000	2592000	1	0	2025-12-04 15:36:24.815+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:36:24.697869+00	2025-12-04 15:37:15.1761+00	\N	universal-auth
6c8bc6ca-2eae-432b-bd3a-c7b85361b618	2592000	2592000	1	0	2025-12-04 15:36:44.12+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:36:43.833723+00	2025-12-04 15:37:44.328666+00	\N	universal-auth
ba89b506-8e03-492e-b66b-73b35f7395f2	2592000	2592000	1	0	2025-12-04 15:37:07.251+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:37:07.148187+00	2025-12-04 15:37:58.402048+00	\N	universal-auth
dfac3da5-023a-4d24-8e4b-ab487e69a26b	2592000	2592000	1	0	2025-12-04 15:37:47.845+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:37:47.730591+00	2025-12-04 15:38:55.193469+00	\N	universal-auth
f5c70869-666b-4c5b-9429-6332b397dff5	2592000	2592000	1	0	2025-12-04 15:43:05.25+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:43:05.135716+00	2025-12-04 15:43:59.822474+00	\N	universal-auth
acaf782b-1b2c-4a3f-92cb-038accd4b25f	2592000	2592000	1	0	2025-12-04 15:46:32.1+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:46:31.916539+00	2025-12-04 15:47:30.197566+00	\N	universal-auth
3c2019f9-8dc9-4637-9182-421b5280968a	2592000	2592000	1	0	2025-12-04 15:47:53.793+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:47:53.661666+00	2025-12-04 15:48:52.210685+00	\N	universal-auth
baae3616-b6aa-4dc8-82ad-9206c43b1937	2592000	2592000	1	0	2025-12-04 15:48:53.371+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:48:53.267108+00	2025-12-04 15:49:51.727924+00	\N	universal-auth
229912f1-b966-4ffa-8285-df7dc1778a31	2592000	2592000	1	0	2025-12-04 15:49:34.579+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:49:34.467037+00	2025-12-04 15:50:25.909046+00	\N	universal-auth
a7a21b5e-3d3f-4b4d-a120-ac3ea4195635	2592000	2592000	1	0	2025-12-04 15:50:08.287+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:50:08.176055+00	2025-12-04 15:51:13.475364+00	\N	universal-auth
79d1662e-1c01-4e14-9fea-322cf6bd6fd2	2592000	2592000	1	0	2025-12-04 15:50:35.288+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:50:35.15907+00	2025-12-04 15:51:43.026773+00	\N	universal-auth
311cc286-3105-4191-99c6-6938214f5bad	2592000	2592000	1	0	2025-12-04 15:50:48.504+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:50:48.375844+00	2025-12-04 15:51:50.166191+00	\N	universal-auth
52af1cb4-e982-4920-be71-e28f74d87443	2592000	2592000	1	0	2025-12-04 15:51:55.862+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:51:55.694274+00	2025-12-04 15:53:03.458622+00	\N	universal-auth
8570782f-192e-46a9-8649-1ef67f97209c	2592000	2592000	1	0	2025-12-04 15:58:16.563+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:58:16.467043+00	2025-12-04 15:59:07.356693+00	\N	universal-auth
d994d9eb-dd35-4c54-942a-7adedd33bcfb	2592000	2592000	1	0	2025-12-04 16:01:45.367+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:01:45.228904+00	2025-12-04 16:02:46.287492+00	\N	universal-auth
66b5d40c-9ba4-472b-9f87-a3cdf18bdf00	2592000	2592000	1	0	2025-12-04 16:02:03.131+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:02:03.000836+00	2025-12-04 16:03:06.192677+00	\N	universal-auth
c8447660-bae4-495f-853f-8c43144e91d2	2592000	2592000	1	0	2025-12-04 16:04:19.918+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:04:19.825775+00	2025-12-04 16:05:28.431029+00	\N	universal-auth
0be6aa80-5a8b-4dae-9872-be3f000f543d	2592000	2592000	1	0	2025-12-04 16:04:59.863+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:04:59.76254+00	2025-12-04 16:05:53.56143+00	\N	universal-auth
a054de85-d80d-4355-8062-10a44e116e2c	2592000	2592000	1	0	2025-12-04 16:05:38.295+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:05:38.170985+00	2025-12-04 16:06:46.230643+00	\N	universal-auth
099b4691-693f-404e-bad7-ba8de708d52c	2592000	2592000	1	0	2025-12-04 16:05:46.816+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:05:46.661573+00	2025-12-04 16:06:51.960446+00	\N	universal-auth
481024bd-f535-4c6f-bafd-7d43bd9c9d34	2592000	2592000	1	0	2025-12-04 16:06:00.108+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:06:00.01515+00	2025-12-04 16:06:53.821198+00	\N	universal-auth
2fa50a1e-62e7-49e7-827d-85bff8cda78e	2592000	2592000	1	0	2025-12-04 16:08:24.166+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:08:24.032856+00	2025-12-04 16:09:31.977234+00	\N	universal-auth
51dbb712-aa80-41fe-b2d7-eda49da5e9ec	2592000	2592000	1	0	2025-12-04 16:11:29.119+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:11:29.015807+00	2025-12-04 16:12:31.907981+00	\N	universal-auth
053610e0-27db-4cab-8fea-30eedfbafe21	2592000	2592000	1	0	2025-12-04 16:11:42.927+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:11:42.833313+00	2025-12-04 16:12:35.124448+00	\N	universal-auth
ab7b5fc1-ffb3-4fbb-a1c2-0bf7d28c12e5	2592000	2592000	1	0	2025-12-04 15:59:45.968+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 15:59:45.852149+00	2025-12-04 16:00:52.506707+00	\N	universal-auth
00e46b9d-a605-41f8-bb00-bc2ced21b136	2592000	2592000	1	0	2025-12-04 16:02:11.517+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:02:11.410289+00	2025-12-04 16:03:15.438416+00	\N	universal-auth
638f5cc5-50d0-4c38-8aaa-2adebd072269	2592000	2592000	1	0	2025-12-04 16:05:16.714+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:05:16.619768+00	2025-12-04 16:06:24.41845+00	\N	universal-auth
9ea7a878-5d78-4f89-8d7a-9f1cb09f34cd	2592000	2592000	1	0	2025-12-04 16:05:30.862+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:05:30.734489+00	2025-12-04 16:06:29.647927+00	\N	universal-auth
b7cfe215-8df4-4b09-8030-017c8d90195b	2592000	2592000	1	0	2025-12-04 16:07:13.366+00	\N	f	bf3e15c0-464c-4119-9e3d-6ad38bf1975e	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-12-04 16:07:13.240188+00	2025-12-04 16:08:07.740292+00	\N	universal-auth
\.


--
-- Data for Name: identity_aws_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_aws_auths (id, "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "accessTokenTrustedIps", "createdAt", "updatedAt", "identityId", type, "stsEndpoint", "allowedPrincipalArns", "allowedAccountIds") FROM stdin;
\.


--
-- Data for Name: identity_azure_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_azure_auths (id, "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "accessTokenTrustedIps", "createdAt", "updatedAt", "identityId", "tenantId", resource, "allowedServicePrincipalIds") FROM stdin;
\.


--
-- Data for Name: identity_gcp_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_gcp_auths (id, "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "accessTokenTrustedIps", "createdAt", "updatedAt", "identityId", type, "allowedServiceAccounts", "allowedProjects", "allowedZones") FROM stdin;
\.


--
-- Data for Name: identity_kubernetes_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_kubernetes_auths (id, "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "accessTokenTrustedIps", "createdAt", "updatedAt", "identityId", "kubernetesHost", "encryptedCaCert", "caCertIV", "caCertTag", "encryptedTokenReviewerJwt", "tokenReviewerJwtIV", "tokenReviewerJwtTag", "allowedNamespaces", "allowedNames", "allowedAudience") FROM stdin;
a4d3086d-acae-4de6-89d8-f35378b9d2d7	2592000	2592000	0	[{"type": "ipv4", "prefix": 0, "ipAddress": "0.0.0.0"}, {"type": "ipv6", "prefix": 0, "ipAddress": "::"}]	2025-11-11 19:32:12.241973+00	2025-11-11 19:32:12.241973+00	a33a0079-5945-4e32-9987-14f21d2e5236	https://10.1.1.13:6443		MU8r3z4mCuvrb8gg	3/vF2UMwF04fq+djZxYnhg==	2Uvy5oQDX9NzBQtYUb7nyaBgktkAM4jhDx7vtnH+aiMQLuyqODLlKCC6D5TFb517W/PH8hwF9fwwl9ptp2Nt9BVNlUT+GMgOAXquxH2TGCS25/zNJlwx6qYWCpKietSIPb4JljZpoHEKg4VmmyFGE2SjpFaY8MfMJfM5a5MsSC4wYFGGoms0UOyBTzczTlxcQ0ksp/FRpOH2nurT0ngMsmDjUT+Yy0waZuTz7rhe8buPDILiRWkqy4pRVVGuzienxTIIPTrm9MxPwL5xDhJY4NJw2XUZdkplFOIYaWw/Dtcr/9biKI0p1f16/ABKBFPQcgHYJsTR2syOWGrRUd+lfmD+yy13fNe+cltC233GGPaGL7MsgB7s4EQ5kyfiZh3eQJJoAxArcsgyeZnFmj8yzXJQZUdA9lCiivklCg+F6FWD4RfLl/7fVhUlJNDtrUhhws0XNtrtYqWfuQgHjbtWcA+W604SjpWXRU30yeJXj+cFjNn5sUGK3uRssw/oyS1cxpETvu13XltGrbmaImm5eP4Cq8HHwU8pwNn+GYw0BDqaT600tn5jBBJrwj0kcBM5/OOExKYcdzObM7IMGltGMLuE+jD2Yg9zHGP4GFVSISBY/0Lbu3X1rbDEmKyHMwDXD2QxonBENwe07Px3PD2HKWLCVgXUyAhVdprAjVTKZjnWTNXaGdvCmxpp7qz33Tjxs+83NIyxZNAeApjgfQTpdDIX/BKVtNnIqfmX8cycb7P9hOC463E3CW1JMFMiAVRyB0eTpihTJZdD/MhWC7XpjiyFy3ylBXutKqXQtrqKrbAvHSnOr2RkhBT8L41VF7KxmGhSgGutuGmucw8r/RnwFzfwuDtPqpr/3p8WsUXxD/4BJLZ2G4qD8l538gONSv+4s9+gn8A9FIwa9vHHJzDbo1KqfD8+N62BZuLCMr4TYLOmzBfFejnXHHrBtEjN6kXfcjy4UT3++vCeWbm7WDOo4KdgErf7TweD0WLmB9A1+RxKoy5kXNERsBRtzhzhpp2F2kcxuWGE0XeUUY0oHqav3bnZB7qU4Cot5WLc4BmQQR7xQUC6gd/aJSspx1jGVvMiSJ+eg38fmjyW2F1TMN7KyCRef89tRXcbtTcgiglk9YERWEDz8vwTx8h96cSv/bmNvmFQ2gjsXAcD7DKdzaTl9l5U8vIGbldbBII0N//hEvrK3YNp23B2Q0+5znkTdi2iJ1niIGJ+QWPflJrBvRDh1ynmiFkLtA2+L8n8/gIMXMOnswOALnwQWGN/Y/zKELj/Avc=	VJV5vqWX8X/KIBA1	6Mmb1xt85JWOaHEgiujjww==			
\.


--
-- Data for Name: identity_metadata; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_metadata (id, key, value, "orgId", "userId", "identityId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: identity_oidc_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_oidc_auths (id, "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "accessTokenTrustedIps", "identityId", "oidcDiscoveryUrl", "encryptedCaCert", "caCertIV", "caCertTag", "boundIssuer", "boundAudiences", "boundClaims", "boundSubject", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: identity_org_memberships; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_org_memberships (id, role, "roleId", "orgId", "createdAt", "updatedAt", "identityId") FROM stdin;
f936059e-5788-4c87-bc8d-c34f55c9b01c	member	\N	c487807e-8e63-4847-8e80-12bdf173b280	2025-10-22 15:54:01.84996+00	2025-10-22 15:54:01.84996+00	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0
d2888c12-ac49-4eac-9af8-6feb64cb7f30	member	\N	c487807e-8e63-4847-8e80-12bdf173b280	2025-11-11 19:25:24.472415+00	2025-11-11 19:32:37.313291+00	a33a0079-5945-4e32-9987-14f21d2e5236
\.


--
-- Data for Name: identity_project_additional_privilege; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_project_additional_privilege (id, slug, "projectMembershipId", "isTemporary", "temporaryMode", "temporaryRange", "temporaryAccessStartTime", "temporaryAccessEndTime", permissions, "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: identity_project_membership_role; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_project_membership_role (id, role, "projectMembershipId", "customRoleId", "isTemporary", "temporaryMode", "temporaryRange", "temporaryAccessStartTime", "temporaryAccessEndTime", "createdAt", "updatedAt") FROM stdin;
d571ae7b-d313-4eeb-9d45-2b0733b7671a	viewer	45609dbe-fc79-4c15-8405-e356b0cb8622	\N	f	\N	\N	\N	\N	2025-10-22 15:56:28.043806+00	2025-10-22 15:56:28.043806+00
c771ee60-4895-442a-a6ed-521022f1024d	viewer	5b6f7ee4-e447-444f-89b9-979670bf6c14	\N	f	\N	\N	\N	\N	2025-11-11 19:32:53.800029+00	2025-11-11 19:32:53.800029+00
dec6fadb-87c0-4317-bd42-3ec3796abf13	viewer	72033fde-73c3-4c0a-b3b6-8e5795289dae	\N	f	\N	\N	\N	\N	2025-12-08 19:01:17.566086+00	2025-12-08 19:01:17.566086+00
5f4be12d-3822-46a3-803f-5ca6ceb6deab	viewer	6207a4c6-882d-426a-80e2-350e0b43ab50	\N	f	\N	\N	\N	\N	2025-12-10 16:47:47.361537+00	2025-12-10 16:47:47.361537+00
eb45fee9-20ee-42b8-80ef-c741d55a83bc	member	790f979d-4abd-4179-b10a-2c3ebd97e59c	\N	f	\N	\N	\N	\N	2025-12-10 17:14:20.133556+00	2025-12-10 17:14:20.133556+00
8a965534-3080-46a0-8101-f942c9f8f4a6	viewer	a89180ce-f139-4ff7-955a-0fcdd1f54c50	\N	f	\N	\N	\N	\N	2025-12-16 21:18:48.380992+00	2025-12-16 21:18:48.380992+00
\.


--
-- Data for Name: identity_project_memberships; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_project_memberships (id, "projectId", "identityId", "createdAt", "updatedAt") FROM stdin;
45609dbe-fc79-4c15-8405-e356b0cb8622	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0	2025-10-22 15:56:28.043806+00	2025-10-22 15:56:28.043806+00
5b6f7ee4-e447-444f-89b9-979670bf6c14	0460652a-8f73-4bd8-b570-d6c346c19c69	a33a0079-5945-4e32-9987-14f21d2e5236	2025-11-11 19:32:53.800029+00	2025-11-11 19:32:53.800029+00
72033fde-73c3-4c0a-b3b6-8e5795289dae	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-08 19:01:17.566086+00	2025-12-08 19:01:17.566086+00
6207a4c6-882d-426a-80e2-350e0b43ab50	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 16:47:47.361537+00	2025-12-10 16:47:47.361537+00
790f979d-4abd-4179-b10a-2c3ebd97e59c	fd4db84c-2090-4f71-89ae-4d2dfc96dd79	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-10 17:14:20.133556+00	2025-12-10 17:14:20.133556+00
a89180ce-f139-4ff7-955a-0fcdd1f54c50	f89b9690-e380-499f-bd5f-b134e4b96731	a33a0079-5945-4e32-9987-14f21d2e5236	2025-12-16 21:18:48.380992+00	2025-12-16 21:18:48.380992+00
\.


--
-- Data for Name: identity_token_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_token_auths (id, "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "accessTokenTrustedIps", "createdAt", "updatedAt", "identityId") FROM stdin;
\.


--
-- Data for Name: identity_ua_client_secrets; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_ua_client_secrets (id, description, "clientSecretPrefix", "clientSecretHash", "clientSecretLastUsedAt", "clientSecretNumUses", "clientSecretNumUsesLimit", "clientSecretTTL", "isClientSecretRevoked", "createdAt", "updatedAt", "identityUAId") FROM stdin;
bf3e15c0-464c-4119-9e3d-6ad38bf1975e		80b1	$2b$10$Fsk6CPWqCjIdUlCcnurha.NcsBkr2PCXtm9.nCoMm1pw5Td2q.wFa	2025-12-04 22:23:21.302+00	2293	0	0	f	2025-10-22 15:55:46.876308+00	2025-12-04 22:23:21.301484+00	a3aa0056-f344-4ebb-a6f2-febedd33c216
\.


--
-- Data for Name: identity_universal_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.identity_universal_auths (id, "clientId", "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "clientSecretTrustedIps", "accessTokenTrustedIps", "createdAt", "updatedAt", "identityId") FROM stdin;
a3aa0056-f344-4ebb-a6f2-febedd33c216	3d4dcd9c-1f59-4268-b330-3ab6573cd32a	2592000	2592000	0	[{"type": "ipv4", "prefix": 0, "ipAddress": "0.0.0.0"}, {"type": "ipv6", "prefix": 0, "ipAddress": "::"}]	[{"type": "ipv4", "prefix": 0, "ipAddress": "0.0.0.0"}, {"type": "ipv6", "prefix": 0, "ipAddress": "::"}]	2025-10-22 15:54:01.908185+00	2025-10-22 15:54:01.908185+00	b34a34f5-0f92-4fc6-9e15-68f9971fc1a0
437a486d-430e-45e5-a4ae-e943aff1ab2c	c8a30896-09ae-4cb2-960d-6c0b2cc33505	2592000	2592000	0	[{"type": "ipv4", "prefix": 0, "ipAddress": "0.0.0.0"}, {"type": "ipv6", "prefix": 0, "ipAddress": "::"}]	[{"type": "ipv4", "prefix": 0, "ipAddress": "0.0.0.0"}, {"type": "ipv6", "prefix": 0, "ipAddress": "::"}]	2025-11-11 19:25:24.528871+00	2025-11-11 19:25:24.528871+00	a33a0079-5945-4e32-9987-14f21d2e5236
\.


--
-- Data for Name: incident_contacts; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.incident_contacts (id, email, "createdAt", "updatedAt", "orgId") FROM stdin;
\.


--
-- Data for Name: infisical_migrations; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.infisical_migrations (id, name, batch, migration_time) FROM stdin;
1	20231128072457_user.ts	1	2025-10-22 15:21:05.04+00
2	20231128092347_user-encryption-key.ts	1	2025-10-22 15:21:05.095+00
3	20231129072939_auth-token.ts	1	2025-10-22 15:21:05.134+00
4	20231130072734_auth-token-session.ts	1	2025-10-22 15:21:05.173+00
5	20231201151432_backup-key.ts	1	2025-10-22 15:21:05.22+00
6	20231204092737_organization.ts	1	2025-10-22 15:21:05.284+00
7	20231204092747_org-membership.ts	1	2025-10-22 15:21:05.363+00
8	20231205151331_incident-contact.ts	1	2025-10-22 15:21:05.399+00
9	20231207055643_user-action.ts	1	2025-10-22 15:21:05.428+00
10	20231207055701_super-admin.ts	1	2025-10-22 15:21:05.455+00
11	20231207105059_api-key.ts	1	2025-10-22 15:21:05.498+00
12	20231212110939_project.ts	1	2025-10-22 15:21:05.624+00
13	20231212110946_project-membership.ts	1	2025-10-22 15:21:05.701+00
14	20231218092441_secret-folder.ts	1	2025-10-22 15:21:05.756+00
15	20231218092508_secret-import.ts	1	2025-10-22 15:21:05.8+00
16	20231218092517_secret-tag.ts	1	2025-10-22 15:21:05.843+00
17	20231218103423_secret.ts	1	2025-10-22 15:21:05.963+00
18	20231220052508_secret-version.ts	1	2025-10-22 15:21:06.028+00
19	20231222092113_project-bot.ts	1	2025-10-22 15:21:06.082+00
20	20231222172455_integration.ts	1	2025-10-22 15:21:06.162+00
21	20231225072545_service-token.ts	1	2025-10-22 15:21:06.206+00
22	20231225072552_webhook.ts	1	2025-10-22 15:21:06.25+00
23	20231228074856_identity.ts	1	2025-10-22 15:21:06.288+00
24	20231228074908_identity-universal-auth.ts	1	2025-10-22 15:21:06.372+00
25	20231228075011_identity-access-token.ts	1	2025-10-22 15:21:06.407+00
26	20231228075023_identity-membership.ts	1	2025-10-22 15:21:06.482+00
27	20240101054849_secret-approval-policy.ts	1	2025-10-22 15:21:06.544+00
28	20240101104907_secret-approval-request.ts	1	2025-10-22 15:21:06.699+00
29	20240102152111_secret-rotation.ts	1	2025-10-22 15:21:06.763+00
30	20240104140641_secret-snapshot.ts	1	2025-10-22 15:21:06.84+00
31	20240107153439_saml-config.ts	1	2025-10-22 15:21:06.884+00
32	20240107163155_org-bot.ts	1	2025-10-22 15:21:06.933+00
33	20240108134148_audit-log.ts	1	2025-10-22 15:21:06.974+00
34	20240111051011_secret-scanning.ts	1	2025-10-22 15:21:07.123+00
35	20240113103743_trusted-ip.ts	1	2025-10-22 15:21:07.159+00
36	20240204171758_org-based-auth.ts	1	2025-10-22 15:21:07.18+00
37	20240208234120_scim-token.ts	1	2025-10-22 15:21:07.211+00
38	20240216154123_ghost_users.ts	1	2025-10-22 15:21:07.265+00
39	20240222201806_admin-signup-control.ts	1	2025-10-22 15:21:07.279+00
40	20240226094411_instance-id.ts	1	2025-10-22 15:21:07.31+00
41	20240307232900_integration-last-used.ts	1	2025-10-22 15:21:07.319+00
42	20240311210135_ldap-config.ts	1	2025-10-22 15:21:07.433+00
43	20240312162549_temp-roles.ts	1	2025-10-22 15:21:07.482+00
44	20240312162556_temp-role-identity.ts	1	2025-10-22 15:21:07.528+00
45	20240318164718_dynamic-secret.ts	1	2025-10-22 15:21:07.618+00
46	20240326172010_project-user-additional-privilege.ts	1	2025-10-22 15:21:07.659+00
47	20240326172011_machine-identity-additional-privilege.ts	1	2025-10-22 15:21:07.699+00
48	20240405000045_org-memberships-unique-constraint.ts	1	2025-10-22 15:21:07.728+00
49	20240412174842_group.ts	1	2025-10-22 15:21:07.864+00
50	20240414192520_drop-role-roleid-project-membership.ts	1	2025-10-22 15:21:07.948+00
51	20240417032913_pending-group-addition.ts	1	2025-10-22 15:21:07.959+00
52	20240423023203_ldap-config-groups.ts	1	2025-10-22 15:21:08.007+00
53	20240424235842_user-search-filter.ts	1	2025-10-22 15:21:08.021+00
54	20240429154610_audit-log-index.ts	1	2025-10-22 15:21:08.11+00
55	20240503101144_audit-log-stream.ts	1	2025-10-22 15:21:08.166+00
56	20240507032811_trusted-saml-ldap-emails.ts	1	2025-10-22 15:21:08.211+00
57	20240507162140_access-approval-policy.ts	1	2025-10-22 15:21:08.295+00
58	20240507162141_access.ts	1	2025-10-22 15:21:08.367+00
59	20240507210655_identity-aws-auth.ts	1	2025-10-22 15:21:08.427+00
60	20240514041650_identity-gcp-auth.ts	1	2025-10-22 15:21:08.483+00
61	20240514141809_inline-secret-reference-sync.ts	1	2025-10-22 15:21:08.53+00
62	20240518142614_kubernetes-auth.ts	1	2025-10-22 15:21:08.587+00
63	20240520064127_add-integration-sync-status.ts	1	2025-10-22 15:21:08.64+00
64	20240522193447_index-audit-logs-project-id-org-id.ts	1	2025-10-22 15:21:08.706+00
65	20240522203425_index-secret-snapshot-secrets-envid.ts	1	2025-10-22 15:21:08.744+00
66	20240522204414_index-secret-version-envId.ts	1	2025-10-22 15:21:08.784+00
67	20240522212706_secret-snapshot-secrets-index-on-snapshotId.ts	1	2025-10-22 15:21:08.824+00
68	20240522221147_secret-snapshot-folder-index-on-snapshotId.ts	1	2025-10-22 15:21:08.865+00
69	20240522225402_secrets-index-on-folder-id-user-id.ts	1	2025-10-22 15:21:08.924+00
70	20240523003158_audit-log-add-expireAt-index.ts	1	2025-10-22 15:21:08.956+00
71	20240527073740_identity-azure-auth.ts	1	2025-10-22 15:21:09.11+00
72	20240528153905_add-user-account-mfa-locking.ts	1	2025-10-22 15:21:09.172+00
73	20240528190137_secret_sharing.ts	1	2025-10-22 15:21:09.273+00
74	20240529060752_snap-shot-secret-index-secretversionid.ts	1	2025-10-22 15:21:09.325+00
75	20240529203152_secret_sharing.ts	1	2025-10-22 15:21:09.347+00
76	20240530044702_universal-text-in-secret-sharing.ts	1	2025-10-22 15:21:09.412+00
77	20240531220007_secret-replication.ts	1	2025-10-22 15:21:09.603+00
78	20240603075514_kms.ts	1	2025-10-22 15:21:09.811+00
79	20240609133400_private-key-handoff.ts	1	2025-10-22 15:21:09.895+00
80	20240610181521_add-consecutive-failed-password-attempts-user.ts	1	2025-10-22 15:21:09.943+00
81	20240612200518_add-pit-version-limit.ts	1	2025-10-22 15:21:09.993+00
82	20240614010847_custom-rate-limits-for-self-hosting.ts	1	2025-10-22 15:21:10.058+00
83	20240614115952_tag-machine-identity.ts	1	2025-10-22 15:21:10.076+00
84	20240614154212_certificate-mgmt.ts	1	2025-10-22 15:21:10.626+00
85	20240614184133_make-secret-sharing-public.ts	1	2025-10-22 15:21:10.704+00
86	20240624161942_add-oidc-auth.ts	1	2025-10-22 15:21:10.839+00
87	20240624172027_default-saml-ldap-org.ts	1	2025-10-22 15:21:10.862+00
88	20240624221840_certificate-alt-names.ts	1	2025-10-22 15:21:10.887+00
89	20240626111536_integration-auth-aws-assume-role.ts	1	2025-10-22 15:21:10.938+00
90	20240626115035_admin-login-method-config.ts	1	2025-10-22 15:21:10.962+00
91	20240626171758_add-ldap-unique-user-attribute.ts	1	2025-10-22 15:21:10.975+00
92	20240626171943_configurable-audit-log-retention.ts	1	2025-10-22 15:21:10.992+00
93	20240627173239_add-oidc-updated-at-trigger.ts	1	2025-10-22 15:21:10.998+00
94	20240701143900_member-project-favorite.ts	1	2025-10-22 15:21:11.017+00
95	20240702055253_add-encrypted-webhook-url.ts	1	2025-10-22 15:21:11.072+00
96	20240702131735_secret-approval-groups.ts	1	2025-10-22 15:21:11.179+00
97	20240702175124_identity-token-auth.ts	1	2025-10-22 15:21:11.223+00
98	20240704161322_identity-access-token-name.ts	1	2025-10-22 15:21:11.258+00
99	20240708100026_external-kms.ts	1	2025-10-22 15:21:11.657+00
100	20240710045107_identity-oidc-auth.ts	1	2025-10-22 15:21:11.751+00
101	20240715113110_org-membership-active-status.ts	1	2025-10-22 15:21:11.854+00
102	20240717184929_add-enforcement-level-secrets-policies.ts	1	2025-10-22 15:21:11.878+00
103	20240717194958_add-enforcement-level-access-policies.ts	1	2025-10-22 15:21:11.901+00
104	20240718170955_add-access-secret-sharing.ts	1	2025-10-22 15:21:11.942+00
105	20240719182539_add-bypass-reason-secret-approval-requets.ts	1	2025-10-22 15:21:11.993+00
106	20240724101056_access-request-groups.ts	1	2025-10-22 15:21:12.208+00
107	20240728010334_secret-sharing-name.ts	1	2025-10-22 15:21:12.277+00
108	20240730181830_add-org-kms-data-key.ts	1	2025-10-22 15:21:12.306+00
109	20240730181840_add-project-data-key.ts	1	2025-10-22 15:21:12.345+00
110	20240730181850_secret-v2.ts	1	2025-10-22 15:21:12.874+00
111	20240802181855_ca-cert-version.ts	1	2025-10-22 15:21:12.957+00
112	20240806083221_secret-sharing-password.ts	1	2025-10-22 15:21:12.977+00
113	20240806113425_remove-creation-limit-rate-limit.ts	1	2025-10-22 15:21:12.997+00
114	20240806185442_drop-tag-name.ts	1	2025-10-22 15:21:13.018+00
115	20240818024923_cert-alerting.ts	1	2025-10-22 15:21:13.124+00
116	20240818184238_add-certificate-template.ts	1	2025-10-22 15:21:13.189+00
117	20240819092916_certificate-template-est-configuration.ts	1	2025-10-22 15:21:13.237+00
118	20240821212643_crl-ca-secret-binding.ts	1	2025-10-22 15:21:13.27+00
119	20240830142938_native-slack-integration.ts	1	2025-10-22 15:21:13.424+00
120	20240909145938_cert-template-enforcement.ts	1	2025-10-22 15:21:13.45+00
121	20240910070128_add-pki-key-usages.ts	1	2025-10-22 15:21:13.497+00
122	20240918005344_add-group-approvals.ts	1	2025-10-22 15:21:13.559+00
123	20240924100329_identity-metadata.ts	1	2025-10-22 15:21:13.6+00
124	20240925100349_managed-secret-sharing.ts	1	2025-10-22 15:21:13.763+00
125	20240930072738_add-oidc-auth-enforced-to-org.ts	1	2025-10-22 15:21:13.784+00
126	20241003220151_kms-key-cmek-alterations.ts	1	2025-10-22 15:21:13.857+00
127	20241005170802_kms-keys-temp-slug-col.ts	1	2025-10-22 15:21:13.876+00
128	20241007052025_make-audit-log-independent.ts	1	2025-10-22 15:21:13.927+00
129	20241007202149_default-org-membership-roles.ts	1	2025-10-22 15:21:13.948+00
130	20241008172622_project-permission-split.ts	1	2025-10-22 15:21:13.966+00
131	20241014084900_identity-multiple-auth-methods.ts	1	2025-10-22 15:21:13.999+00
132	20241015084434_increase-identity-metadata-col-length.ts	1	2025-10-22 15:21:14.022+00
133	20241015145450_external-group-org-role-mapping.ts	1	2025-10-22 15:21:14.081+00
134	20241016183616_add-org-enforce-mfa.ts	1	2025-10-22 15:21:14.102+00
135	20241021114650_add-missing-org-cascade-references.ts	1	2025-10-22 15:21:14.132+00
\.


--
-- Data for Name: infisical_migrations_lock; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.infisical_migrations_lock (index, is_locked) FROM stdin;
1	0
\.


--
-- Data for Name: integration_auths; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.integration_auths (id, integration, "teamId", url, namespace, "accountId", "refreshCiphertext", "refreshIV", "refreshTag", "accessIdCiphertext", "accessIdIV", "accessIdTag", "accessCiphertext", "accessIV", "accessTag", "accessExpiresAt", metadata, algorithm, "keyEncoding", "projectId", "createdAt", "updatedAt", "awsAssumeIamRoleArnCipherText", "awsAssumeIamRoleArnIV", "awsAssumeIamRoleArnTag", "encryptedAccess", "encryptedAccessId", "encryptedRefresh", "encryptedAwsAssumeIamRoleArn") FROM stdin;
\.


--
-- Data for Name: integrations; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.integrations (id, "isActive", url, app, "appId", "targetEnvironment", "targetEnvironmentId", "targetService", "targetServiceId", owner, path, region, scope, integration, metadata, "integrationAuthId", "envId", "secretPath", "createdAt", "updatedAt", "lastUsed", "isSynced", "syncMessage", "lastSyncJobId") FROM stdin;
\.


--
-- Data for Name: internal_kms; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.internal_kms (id, "encryptedKey", "encryptionAlgorithm", version, "kmsKeyId") FROM stdin;
3ce8167f-6474-4738-84c6-d955f28f94b4	\\x25ef6e1b0c52d5fce1d227e3e4dc5149d92a411185953dad605b77f93a0675f790601bae62383b9e96109d8c82759713725d99ac8db9fd7d95def26e	aes-256-gcm	1	fe864b48-bd16-4142-b6ad-cb2c5b85429f
19619917-e5df-4dec-afe2-d380deb666ec	\\x18184a70646823fca21720e3e6cc602eaab532191bafa54088de97e1da0a0c83f98547d79c24b7e17ce59fae544702a189663dfd8fed502351146914	aes-256-gcm	1	035443c4-5e5d-4c48-950b-8dc3d507d791
d4148345-6bf1-459b-be79-f6538f08fb03	\\x9f3c842921e90799b30e24fa54751c6171e158d65460905e2014d3405f61423f9c401c9aa16ba846d270d01800a77b795d7f59ed820a2f0cffb7fd45	aes-256-gcm	1	8ee6576d-42dd-4668-9563-063467f778c6
eafa7274-ea76-4d06-9464-657be7cb5996	\\xa87bbddd24135933ee65ea4fd8155d34a97d1f0710a7a9956b4f7dece4ba9adf1627c35a29b4ffccc67b3bc2ec17e441f6590da307484268eb4ddc79	aes-256-gcm	1	84c06812-5ede-4540-b4de-8c63a942b1db
035f520e-fe2a-455c-b513-84dbffff0421	\\x09013e90174a4a106b7320e3e2724c7ea5f41471c96a9e486cbf044ee057e265244e621f835f893514715c9ff21030ed24e1345befa874e5541df62f	aes-256-gcm	1	c0bbabc4-f87d-49a0-9d43-0b15e8bb4294
06739efa-8b78-4e8e-8211-29b280e5c644	\\x7ff1c808acbdf8c4ea8696df2cf7e85c94a549758421afa937d9ebf31b541c681f8fff7c1e06554fd1e5ba332b74b26cf20534430d4a179118004b6e	aes-256-gcm	1	6d71b4f7-407d-433c-a337-f59b43a69d89
\.


--
-- Data for Name: internal_kms_key_version; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.internal_kms_key_version (id, "encryptedKey", version, "internalKmsId") FROM stdin;
\.


--
-- Data for Name: kms_keys; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.kms_keys (id, description, "isDisabled", "isReserved", "orgId", name, "createdAt", "updatedAt", "projectId", slug) FROM stdin;
fe864b48-bd16-4142-b6ad-cb2c5b85429f	\N	f	t	c487807e-8e63-4847-8e80-12bdf173b280	kzj27vbr	2025-10-22 15:34:24.635882+00	2025-10-22 15:34:24.635882+00	\N	\N
035443c4-5e5d-4c48-950b-8dc3d507d791	\N	f	t	c487807e-8e63-4847-8e80-12bdf173b280	cvzwo8e4	2025-11-11 19:17:04.53358+00	2025-11-11 19:17:04.53358+00	\N	\N
8ee6576d-42dd-4668-9563-063467f778c6	\N	f	t	c487807e-8e63-4847-8e80-12bdf173b280	gcgo6esg	2025-12-08 17:38:59.484236+00	2025-12-08 17:38:59.484236+00	\N	\N
84c06812-5ede-4540-b4de-8c63a942b1db	\N	f	t	c487807e-8e63-4847-8e80-12bdf173b280	zlvpo1mt	2025-12-10 16:47:35.686531+00	2025-12-10 16:47:35.686531+00	\N	\N
c0bbabc4-f87d-49a0-9d43-0b15e8bb4294	\N	f	t	c487807e-8e63-4847-8e80-12bdf173b280	fdg9oafk	2025-12-10 16:51:46.372888+00	2025-12-10 16:51:46.372888+00	\N	\N
6d71b4f7-407d-433c-a337-f59b43a69d89	\N	f	t	c487807e-8e63-4847-8e80-12bdf173b280	jy7ger9w	2025-12-16 21:18:36.296377+00	2025-12-16 21:18:36.296377+00	\N	\N
\.


--
-- Data for Name: kms_root_config; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.kms_root_config (id, "encryptedRootKey") FROM stdin;
00000000-0000-0000-0000-000000000000	\\x35694709c081b2906c95b8b5fdbf3fcf3ab56766672c2b753a526df2bfb4b9574c5743c192455ea3ff944b701e6a06758b45a1ed3a56ff439da1ae56
\.


--
-- Data for Name: ldap_configs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.ldap_configs (id, "orgId", "isActive", url, "encryptedBindDN", "bindDNIV", "bindDNTag", "encryptedBindPass", "bindPassIV", "bindPassTag", "searchBase", "encryptedCACert", "caCertIV", "caCertTag", "createdAt", "updatedAt", "groupSearchBase", "groupSearchFilter", "searchFilter", "uniqueUserAttribute") FROM stdin;
\.


--
-- Data for Name: ldap_group_maps; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.ldap_group_maps (id, "ldapConfigId", "ldapGroupCN", "groupId") FROM stdin;
\.


--
-- Data for Name: oidc_configs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.oidc_configs (id, "discoveryURL", issuer, "authorizationEndpoint", "jwksUri", "tokenEndpoint", "userinfoEndpoint", "encryptedClientId", "configurationType", "clientIdIV", "clientIdTag", "encryptedClientSecret", "clientSecretIV", "clientSecretTag", "allowedEmailDomains", "isActive", "createdAt", "updatedAt", "orgId", "lastUsed") FROM stdin;
\.


--
-- Data for Name: org_bots; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.org_bots (id, name, "publicKey", "encryptedSymmetricKey", "symmetricKeyIV", "symmetricKeyTag", "symmetricKeyAlgorithm", "symmetricKeyKeyEncoding", "encryptedPrivateKey", "privateKeyIV", "privateKeyTag", "privateKeyAlgorithm", "privateKeyKeyEncoding", "orgId", "createdAt", "updatedAt") FROM stdin;
4371e36c-7950-40c2-9ca1-1f9247526478	Admin Org	tWIM9H72/T0WpiwAUyOLau9y83tcSaybVpEqXiD+jFA=	DIrOPLbiYL7kVSIBDEkGkxB9fo4Hun+3Cy0vhlQS0zFQXw1HpFjIF4AhDLM=	++9PHzivnAIRxZtPvKLCAA==	YcU42BA+XN5Zlwor+FyONQ==	aes-256-gcm	utf8	ic72/1jejpYdyh4Mz8boODYBeAkCq4cFkj+U70iUwXD8y4EzzMHKdufRQ8A=	DJ2/3D7YdRm/wZJTY51uXg==	x55avNe3x5P0PXH8WwZkeA==	aes-256-gcm	utf8	c487807e-8e63-4847-8e80-12bdf173b280	2025-10-22 15:25:08.332442+00	2025-10-22 15:25:08.332442+00
\.


--
-- Data for Name: org_memberships; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.org_memberships (id, role, status, "inviteEmail", "createdAt", "updatedAt", "userId", "orgId", "roleId", "projectFavorites", "isActive") FROM stdin;
f0b0fb8f-0f40-45e0-ba60-c70bdae878aa	admin	accepted	\N	2025-10-22 15:25:08.332442+00	2025-10-22 15:25:08.332442+00	0c9fba56-8584-4a79-b9ea-183147b9d42e	c487807e-8e63-4847-8e80-12bdf173b280	\N	\N	t
69cb4c68-5852-4042-843b-7ffbfb87e7b1	admin	accepted	\N	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00	02d439fc-3f86-4889-9792-5cf3bad6f46f	c487807e-8e63-4847-8e80-12bdf173b280	\N	\N	t
0bdcf1ed-2c0c-45ba-94bd-ceeba7275991	admin	accepted	\N	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00	4bbbf546-f610-4234-ad37-1c3c72f95747	c487807e-8e63-4847-8e80-12bdf173b280	\N	\N	t
a8da5e13-96f2-483f-b5a2-2aa3ce8c9bcc	admin	accepted	\N	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00	af0d16ce-271a-485e-81ae-37d56c4d8571	c487807e-8e63-4847-8e80-12bdf173b280	\N	\N	t
b6784669-a802-4b58-b686-19adb8265625	admin	accepted	\N	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00	f1809a0f-6b04-44bd-84b0-3f61775b693d	c487807e-8e63-4847-8e80-12bdf173b280	\N	\N	t
05f98214-13bb-4780-9afb-5f347cac4975	admin	accepted	\N	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00	e5826e5e-82bf-41c0-88bc-a0ddb1a28873	c487807e-8e63-4847-8e80-12bdf173b280	\N	\N	t
f8d94f4a-2c3b-4ff1-9793-b183ec46aa10	admin	accepted	\N	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00	3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	c487807e-8e63-4847-8e80-12bdf173b280	\N	\N	t
\.


--
-- Data for Name: org_roles; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.org_roles (id, name, description, slug, permissions, "createdAt", "updatedAt", "orgId") FROM stdin;
\.


--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.organizations (id, name, "customerId", slug, "createdAt", "updatedAt", "authEnforced", "scimEnabled", "kmsDefaultKeyId", "kmsEncryptedDataKey", "defaultMembershipRole", "enforceMfa") FROM stdin;
c487807e-8e63-4847-8e80-12bdf173b280	hsm	\N	hsm-qq36	2025-10-22 15:25:08.332442+00	2025-10-22 15:27:07.735683+00	f	f	\N	\N	member	f
\.


--
-- Data for Name: pki_alerts; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.pki_alerts (id, "createdAt", "updatedAt", "projectId", "pkiCollectionId", name, "alertBeforeDays", "recipientEmails") FROM stdin;
\.


--
-- Data for Name: pki_collection_items; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.pki_collection_items (id, "createdAt", "updatedAt", "pkiCollectionId", "caId", "certId") FROM stdin;
\.


--
-- Data for Name: pki_collections; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.pki_collections (id, "createdAt", "updatedAt", "projectId", name, description) FROM stdin;
\.


--
-- Data for Name: project_bots; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_bots (id, name, "isActive", "encryptedPrivateKey", "publicKey", iv, tag, algorithm, "keyEncoding", "encryptedProjectKey", "encryptedProjectKeyNonce", "projectId", "senderId", "createdAt", "updatedAt") FROM stdin;
d5258f10-7fee-4389-bd6c-0667e7764642	Infisical Bot (Ghost)	t	gwVG6RrJBOd3I3Wmi6Lm7Zw0jp0yjCcGY5g4zJRvr4TdC2xlm2NrIoGxO7M=	jXc/M4bClcLb1118wGPzOLZKvm/2x/mzR6Qu676/anQ=	giQI7FF4xRFw4iKmWDKpCQ==	0EUf8TekeYzo8DbX/iS9AA==	aes-256-gcm	utf8	mDYQbb6TC2XQ4krf6xq2c2X44eAc008cqS7RAJH/Y/sWcUOYlWY1vxpE/+ioXJqC	XdzgReqLzCz50rSo9rSc9UIoUTgslDWw	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	02d439fc-3f86-4889-9792-5cf3bad6f46f	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
d3b1b0f1-8560-4a35-acec-1d6336914e75	Infisical Bot (Ghost)	t	HuUcoIZr9QZAAdNv8RIeb8tgGebrhHLhAgCSkEUu/LRb+BY+f73q9PtjGc8=	WeCwK6cTgWNpSxk15OjJDTOKrDAVhZMswxkxad4XgS8=	FLl/TY//XRwXoxlgFhYwaw==	JVUEus+JbCb06pbwvQAhfg==	aes-256-gcm	utf8	2TQFcFqKPntrs31Vpp6DMugDK2W5nA3DtE9LW6EkCxzTPYK2NBaIzPabMAlonaYS	OWWAm4LJn8p2b8pMQE+oouYxppJ8DGeS	0460652a-8f73-4bd8-b570-d6c346c19c69	4bbbf546-f610-4234-ad37-1c3c72f95747	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
f4f4a960-125f-426c-9556-d1846ef31769	Infisical Bot (Ghost)	t	1HX5mGsNQQA9M8juhzMQHqP8r6Td4pDahxZjdxm/KzPQukis+/t+tLbsoVs=	QIz3MAoszLBY0Y0ATtE1twK1HA7+dhHoptG41uAFSwU=	cVEXKmBjZupxaZuwa2f3yg==	PdoltbCRRVroAYi/ZXIwyA==	aes-256-gcm	utf8	9K+B3xMlq8yJXE9YoVCQ7misUXORpDMefPMR7rbHNTZjOZfJgXyGDKcooSMymAU9	mUQROMjCsYom7JFeoIu8gYaiJFo02hds	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	af0d16ce-271a-485e-81ae-37d56c4d8571	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
5c357490-97f3-4f41-b5da-a60a182f5861	Infisical Bot (Ghost)	t	fl10AJbyKLkuvzQCnVVxhNr4FdrJ71Wbry0ijhpCSaLea6eUEuLHQLBaWrs=	YFm+DFSIFI5YiIZvKGCbKz669zhZ6RfEbB6+bTfK/Sk=	/awXxmSX/SP9OFHawZroag==	avI61hDwb52lLUZ5a/mYyA==	aes-256-gcm	utf8	MHfspHN+gw/DulqQnCXnBkSRmJyk0jo2ed05EoGtApIYdESt00Hvc4wy2GtGAJv6	mrruFMlj5GWFPHDy+CYQRCUByvMxgJlq	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	f1809a0f-6b04-44bd-84b0-3f61775b693d	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
1859cf1d-164c-4a8f-bf9f-0ea84eb1ebd4	Infisical Bot (Ghost)	t	vfx/tNJf8XoTdPrUvQL0sJzVeWxIErI51qSM+36EsskWyHauwHqTmvjT998=	mYsL2wiKC3Niy7q5RLtmn/U0pfzwO/hZyx4gUbyAO1Y=	36HtfVkATt0tCoL1OaJQBQ==	iddLSfoEYKQuRAfq9Z8FWQ==	aes-256-gcm	utf8	t2a8kkna5K7elF/3VA3uhnXf7k8lFRtCG0JBo1xmQnbKfZTdwMPKLNMBq1HhZzMn	pANqXBf7HPiBgRCUEzZYyR5zH1GcBzNL	fd4db84c-2090-4f71-89ae-4d2dfc96dd79	e5826e5e-82bf-41c0-88bc-a0ddb1a28873	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
d6452635-9fdb-48fb-bab1-89876382d563	Infisical Bot (Ghost)	t	m4UyF/0hYHyen/AN+KyPBn8ZWOdqobVdnsYm0vNzRRMxKw4Z05jehYM/iL4=	DAMipcdmv9TuCnwdk0MisElLlFfRZGQZZ4h/gWtnZFw=	9CYHZDslu4XAjGzRNwLu5w==	1AX5J8cp/CUNUdNvY8hthw==	aes-256-gcm	utf8	OsItwNnnGMc+Q293eppEp7YNz1KvBhoUhmzTZrsL6YFg9nzHNUxziqRLaxMXs+vi	Wd03zBX69EyUsHBkzLE9mLyvpvCCHGeq	f89b9690-e380-499f-bd5f-b134e4b96731	3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
\.


--
-- Data for Name: project_environments; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_environments (id, name, slug, "position", "projectId", "createdAt", "updatedAt") FROM stdin;
a28ceab1-d6a2-404e-b21b-fb9a14194e65	Development	dev	1	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
31fcb5e1-23f2-4589-b779-167352214b1f	Staging	staging	2	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
6b264ab4-f82b-4f0b-b39c-741aeeb507e4	Production	prod	3	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
15a1dd97-f1d2-455f-8328-141644e1f032	Development	dev	1	0460652a-8f73-4bd8-b570-d6c346c19c69	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
5eb8c92e-5aeb-4aa6-8615-13e8a3163a40	Staging	staging	2	0460652a-8f73-4bd8-b570-d6c346c19c69	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
24f31f48-cb28-4bb5-b231-8917e97559e6	Production	prod	3	0460652a-8f73-4bd8-b570-d6c346c19c69	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
ef1eb14f-77c9-48ae-85df-00bd73ca4a85	Development	dev	1	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	Staging	staging	2	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
3e8a705e-9742-43ea-96cb-89fe88aed058	Production	prod	3	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
82732d9d-904b-4f60-bc34-dbd6dfd85b97	Development	dev	1	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
80af13d8-3dcd-41e6-9e1f-6932888266da	Staging	staging	2	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
1bbe551a-fa18-4df7-8897-2d15055d5c28	Production	prod	3	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
b62ee3ae-1ed9-478b-afb3-9a09473ba774	Development	dev	1	fd4db84c-2090-4f71-89ae-4d2dfc96dd79	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
03ebf868-ea91-44d9-9dda-e328e13d3561	Staging	staging	2	fd4db84c-2090-4f71-89ae-4d2dfc96dd79	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
6926a156-9533-45dc-bcb6-b716ab914f46	Production	prod	3	fd4db84c-2090-4f71-89ae-4d2dfc96dd79	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
aaf3c10b-93ec-44cb-9211-cbfc97c13ff3	Development	dev	1	f89b9690-e380-499f-bd5f-b134e4b96731	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
a8048ec8-1200-453e-b7cb-4a0dedb9eb89	Staging	staging	2	f89b9690-e380-499f-bd5f-b134e4b96731	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	Production	prod	3	f89b9690-e380-499f-bd5f-b134e4b96731	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
\.


--
-- Data for Name: project_keys; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_keys (id, "encryptedKey", nonce, "receiverId", "senderId", "projectId", "createdAt", "updatedAt") FROM stdin;
08d35229-4a75-4603-a041-0d5dff5aeef0	mDYQbb6TC2XQ4krf6xq2c2X44eAc008cqS7RAJH/Y/sWcUOYlWY1vxpE/+ioXJqC	XdzgReqLzCz50rSo9rSc9UIoUTgslDWw	02d439fc-3f86-4889-9792-5cf3bad6f46f	02d439fc-3f86-4889-9792-5cf3bad6f46f	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
96b62977-1a26-4073-a5de-a03dc689276c	C/1fcU8lBvPCFiXok/b4ojBKZR1eF+MBy0BOzTL2KZQdSnBRSpe3ZMnJpzDwQe8t	ZdEVRMAOHCp+7i/uds51xSf/fNZ/3TRD	0c9fba56-8584-4a79-b9ea-183147b9d42e	02d439fc-3f86-4889-9792-5cf3bad6f46f	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
731ffcc1-ddc6-460f-9eed-7a7460e98f8d	2TQFcFqKPntrs31Vpp6DMugDK2W5nA3DtE9LW6EkCxzTPYK2NBaIzPabMAlonaYS	OWWAm4LJn8p2b8pMQE+oouYxppJ8DGeS	4bbbf546-f610-4234-ad37-1c3c72f95747	4bbbf546-f610-4234-ad37-1c3c72f95747	0460652a-8f73-4bd8-b570-d6c346c19c69	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
948a6bd4-7662-4d6a-ae60-dea84733e114	RyREXpDUksTha26JDmgHDoGanz5pFpx2qzbdYhjvmbMeT2f67pbTzIxQT9LoLf7b	X6OVefFmkVfhua+0oaNBkYfqYDFcv1hV	0c9fba56-8584-4a79-b9ea-183147b9d42e	4bbbf546-f610-4234-ad37-1c3c72f95747	0460652a-8f73-4bd8-b570-d6c346c19c69	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
957a7bab-b6ce-4dbd-9b22-ed1c1dfb8e38	9K+B3xMlq8yJXE9YoVCQ7misUXORpDMefPMR7rbHNTZjOZfJgXyGDKcooSMymAU9	mUQROMjCsYom7JFeoIu8gYaiJFo02hds	af0d16ce-271a-485e-81ae-37d56c4d8571	af0d16ce-271a-485e-81ae-37d56c4d8571	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
7569f06b-fded-4bee-8de0-fe9ac7f1104c	WG4FrgRuFx9hPwdTrg4RyfCY7THiEIwmqT4AboPYQwDLxE5cJNWShRyLOduZuXju	Iynvcyq6h6vdCv9m3IUVIJopJSodJXWt	0c9fba56-8584-4a79-b9ea-183147b9d42e	af0d16ce-271a-485e-81ae-37d56c4d8571	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
ecec9296-8146-4eb1-92c4-9c240e04cbc5	MHfspHN+gw/DulqQnCXnBkSRmJyk0jo2ed05EoGtApIYdESt00Hvc4wy2GtGAJv6	mrruFMlj5GWFPHDy+CYQRCUByvMxgJlq	f1809a0f-6b04-44bd-84b0-3f61775b693d	f1809a0f-6b04-44bd-84b0-3f61775b693d	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
7da88c9a-a1ed-4896-a219-be94fc52b618	iMR56jZmwZvUk7eQMHuQHvCm0Hb/5O9axbZZ/wrK7HA9NtR9MA9q4BvGvVX0AS19	+cWo4oFg2/MCmCJ6heRP6v9Koydh8dU7	0c9fba56-8584-4a79-b9ea-183147b9d42e	f1809a0f-6b04-44bd-84b0-3f61775b693d	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
ef8051cc-2229-4127-9013-9b59cce1ef66	t2a8kkna5K7elF/3VA3uhnXf7k8lFRtCG0JBo1xmQnbKfZTdwMPKLNMBq1HhZzMn	pANqXBf7HPiBgRCUEzZYyR5zH1GcBzNL	e5826e5e-82bf-41c0-88bc-a0ddb1a28873	e5826e5e-82bf-41c0-88bc-a0ddb1a28873	fd4db84c-2090-4f71-89ae-4d2dfc96dd79	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
f01a5079-f01a-4a4a-87f6-ad2aa765b957	ik1FJPprXTgKFYftxA1M5R0W/KzqlkWqtPYLdfc84jZmIRTxSNZ7OEiMvLIc3iYA	fc/NwP7VjY0dwE/mQhVQ2Rbz0UO7piVw	0c9fba56-8584-4a79-b9ea-183147b9d42e	e5826e5e-82bf-41c0-88bc-a0ddb1a28873	fd4db84c-2090-4f71-89ae-4d2dfc96dd79	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
a67278cb-e804-4e9a-b78e-ed19c3f2f88a	OsItwNnnGMc+Q293eppEp7YNz1KvBhoUhmzTZrsL6YFg9nzHNUxziqRLaxMXs+vi	Wd03zBX69EyUsHBkzLE9mLyvpvCCHGeq	3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	f89b9690-e380-499f-bd5f-b134e4b96731	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
4154279c-e966-452b-a72e-6f84cd8c9b82	qjnvAgNCLCOIgT+HqhJA78lCxi2fL6HnJtZhvYpSqpdTJTAZA5dXnPDoZbtIbbJo	L4xI8zKFwRp6Uzz9efh5AStnf/gu3kSK	0c9fba56-8584-4a79-b9ea-183147b9d42e	3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	f89b9690-e380-499f-bd5f-b134e4b96731	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
\.


--
-- Data for Name: project_memberships; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_memberships (id, "createdAt", "updatedAt", "userId", "projectId") FROM stdin;
15c0e693-c704-446b-b09e-0d96f48ec698	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00	02d439fc-3f86-4889-9792-5cf3bad6f46f	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188
9d517271-d75b-4785-ad41-7bf716deffd6	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00	0c9fba56-8584-4a79-b9ea-183147b9d42e	b4c0d26c-0476-4aa3-962e-a2cdfbfcf188
48461ccc-3b6d-42a1-a7e2-a20ca725ba26	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00	4bbbf546-f610-4234-ad37-1c3c72f95747	0460652a-8f73-4bd8-b570-d6c346c19c69
b91d3343-2a4f-4fb2-996a-ea636eca4e38	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00	0c9fba56-8584-4a79-b9ea-183147b9d42e	0460652a-8f73-4bd8-b570-d6c346c19c69
c5091d96-e177-460c-90a8-127607ad425a	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00	af0d16ce-271a-485e-81ae-37d56c4d8571	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0
c1032b5e-d79e-4660-b4c2-419dd131a627	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00	0c9fba56-8584-4a79-b9ea-183147b9d42e	7b80ec78-9f95-45e6-9e3d-04f1f1401fb0
827617a6-6c7e-4ea1-b020-58443215ddea	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00	f1809a0f-6b04-44bd-84b0-3f61775b693d	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6
0b643c90-a570-4c3d-a6aa-751b30c88bca	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00	0c9fba56-8584-4a79-b9ea-183147b9d42e	5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6
61fc924f-f1a8-4d32-821a-9cdc656a3111	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00	e5826e5e-82bf-41c0-88bc-a0ddb1a28873	fd4db84c-2090-4f71-89ae-4d2dfc96dd79
5b692b18-ff00-4e8e-9512-6d39cff02163	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00	0c9fba56-8584-4a79-b9ea-183147b9d42e	fd4db84c-2090-4f71-89ae-4d2dfc96dd79
3ab3eeb6-09c1-4656-a084-429cc246c9b4	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00	3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	f89b9690-e380-499f-bd5f-b134e4b96731
360c5b5c-fc5b-422f-a142-daec032352ed	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00	0c9fba56-8584-4a79-b9ea-183147b9d42e	f89b9690-e380-499f-bd5f-b134e4b96731
\.


--
-- Data for Name: project_roles; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_roles (id, name, description, slug, permissions, "createdAt", "updatedAt", "projectId", version) FROM stdin;
\.


--
-- Data for Name: project_slack_configs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_slack_configs (id, "projectId", "slackIntegrationId", "isAccessRequestNotificationEnabled", "accessRequestChannels", "isSecretRequestNotificationEnabled", "secretRequestChannels", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: project_user_additional_privilege; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_user_additional_privilege (id, slug, "projectMembershipId", "isTemporary", "temporaryMode", "temporaryRange", "temporaryAccessStartTime", "temporaryAccessEndTime", permissions, "createdAt", "updatedAt", "userId", "projectId") FROM stdin;
\.


--
-- Data for Name: project_user_membership_roles; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.project_user_membership_roles (id, role, "projectMembershipId", "customRoleId", "isTemporary", "temporaryMode", "temporaryRange", "temporaryAccessStartTime", "temporaryAccessEndTime", "createdAt", "updatedAt") FROM stdin;
02e12c78-7642-4022-aa09-fd17ac15dae1	admin	15c0e693-c704-446b-b09e-0d96f48ec698	\N	f	\N	\N	\N	\N	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
d879f893-e6ce-4e46-9b1e-65bbb1a652f7	admin	9d517271-d75b-4785-ad41-7bf716deffd6	\N	f	\N	\N	\N	\N	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00
8e5ff73d-1a10-49ff-a3d8-6da7f060795b	admin	48461ccc-3b6d-42a1-a7e2-a20ca725ba26	\N	f	\N	\N	\N	\N	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
4d149fd9-65ce-475f-a3eb-4f0be59e23f7	admin	b91d3343-2a4f-4fb2-996a-ea636eca4e38	\N	f	\N	\N	\N	\N	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00
476cbd07-231b-4b2e-9df4-c87aea46b6a5	admin	c5091d96-e177-460c-90a8-127607ad425a	\N	f	\N	\N	\N	\N	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
60621a7d-fb12-4a3c-833f-98e3eb99c659	admin	c1032b5e-d79e-4660-b4c2-419dd131a627	\N	f	\N	\N	\N	\N	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00
c1afb641-10c1-4fbf-baf3-93d3384a36c1	admin	827617a6-6c7e-4ea1-b020-58443215ddea	\N	f	\N	\N	\N	\N	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
8c7a02f7-8339-4a43-86dc-cb6d36c2f05d	admin	0b643c90-a570-4c3d-a6aa-751b30c88bca	\N	f	\N	\N	\N	\N	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00
c6b92859-1e25-412c-bc24-b8848a03dc94	admin	61fc924f-f1a8-4d32-821a-9cdc656a3111	\N	f	\N	\N	\N	\N	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
d2b09a37-e083-418d-a567-3583aeb87d01	admin	5b692b18-ff00-4e8e-9512-6d39cff02163	\N	f	\N	\N	\N	\N	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00
75097d87-e9e7-4f94-9d84-9ba674d14cba	admin	3ab3eeb6-09c1-4656-a084-429cc246c9b4	\N	f	\N	\N	\N	\N	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
7c7a064a-55d6-454b-a7af-3544acbcf383	admin	360c5b5c-fc5b-422f-a142-daec032352ed	\N	f	\N	\N	\N	\N	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00
\.


--
-- Data for Name: projects; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.projects (id, name, slug, "autoCapitalization", "orgId", "createdAt", "updatedAt", version, "upgradeStatus", "pitVersionLimit", "kmsCertificateKeyId", "auditLogsRetentionDays", "kmsSecretManagerKeyId", "kmsSecretManagerEncryptedDataKey") FROM stdin;
b4c0d26c-0476-4aa3-962e-a2cdfbfcf188	hsm	hsm-j816	t	c487807e-8e63-4847-8e80-12bdf173b280	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:24.671594+00	3	\N	10	\N	\N	fe864b48-bd16-4142-b6ad-cb2c5b85429f	\\xf483db3716fde1361124b61db6153cc3d80de1dc583aa5bdb21b2df12cb1fe5ed534f6816f34dc81f9b211484c775cf4106a9ce24899ea39d2f0298b763031
0460652a-8f73-4bd8-b570-d6c346c19c69	traefik-openrouter	traefik-openrouter-b-wj-v	t	c487807e-8e63-4847-8e80-12bdf173b280	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:04.556848+00	3	\N	10	\N	\N	035443c4-5e5d-4c48-950b-8dc3d507d791	\\x6aa6d5837667e5a0c3a18b759260a0ede3665be827b9b65e50254c0fa68d7f6dc788d4d08f90cc01f40aa4e39be215d63b44c3f3823b5c74cf695e8a763031
7b80ec78-9f95-45e6-9e3d-04f1f1401fb0	hsm-security-cams	hsm-security-cams-cf2t	t	c487807e-8e63-4847-8e80-12bdf173b280	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:59.504975+00	3	\N	10	\N	\N	8ee6576d-42dd-4668-9563-063467f778c6	\\xd6e08630223ef2681a9e34edc8d95bc9ebaac31a5f5229d91a4405dfe549b5666b009123514dd568414a5f1905f791fa8cb7fcf5367690d870970abf763031
5b6b1cc4-f323-4c1e-8b9a-52771f52d1f6	hsm-monitoring	hsm-monitoring-e-gp-e	t	c487807e-8e63-4847-8e80-12bdf173b280	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:35.711038+00	3	\N	10	\N	\N	84c06812-5ede-4540-b4de-8c63a942b1db	\\x74c9a4511f56b556df626a9e5aaca7e9524a64282766f4da7800112b1c1a6dee99d353c7d19b3bd9103a842b48e8b700ccf085195763045190c33844763031
fd4db84c-2090-4f71-89ae-4d2dfc96dd79	hsm-storage	hsm-storage-gep-v	t	c487807e-8e63-4847-8e80-12bdf173b280	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:46.3875+00	3	\N	10	\N	\N	c0bbabc4-f87d-49a0-9d43-0b15e8bb4294	\\x1a798a252e643159bba86ad63a3769855422c453c823a26b941055a1de3f69fea637423cc9c1f8d28d6b892ad93aac7255e046e0e1ac5287efce7493763031
f89b9690-e380-499f-bd5f-b134e4b96731	hsm-networking	hsm-networking-6-ucf	t	c487807e-8e63-4847-8e80-12bdf173b280	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:36.320413+00	3	\N	10	\N	\N	6d71b4f7-407d-433c-a337-f59b43a69d89	\\x4761cd45b674a345bd19e948fa4f4cfae0168a33b0c1169baa58a24d0c868e87beb76508c5f8a7cd04820ad3b3cb2dfc7f3c759ba6dbb0ae92e87a96763031
\.


--
-- Data for Name: rate_limit; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.rate_limit (id, "readRateLimit", "writeRateLimit", "secretsRateLimit", "authRateLimit", "inviteUserRateLimit", "mfaRateLimit", "publicEndpointLimit", "createdAt", "updatedAt") FROM stdin;
3764f82c-9516-4e4d-a290-bb51a1fed98d	600	200	60	60	30	20	30	2025-10-22 15:21:10.011072+00	2025-10-22 15:21:10.011072+00
00000000-0000-0000-0000-000000000000	600	200	60	60	30	20	30	2025-10-22 15:25:29.431734+00	2025-10-22 15:25:29.431734+00
\.


--
-- Data for Name: saml_configs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.saml_configs (id, "authProvider", "isActive", "encryptedEntryPoint", "entryPointIV", "entryPointTag", "encryptedIssuer", "issuerTag", "issuerIV", "encryptedCert", "certIV", "certTag", "createdAt", "updatedAt", "orgId", "lastUsed") FROM stdin;
\.


--
-- Data for Name: scim_tokens; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.scim_tokens (id, "ttlDays", description, "orgId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_approval_policies; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_policies (id, name, "secretPath", approvals, "envId", "createdAt", "updatedAt", "enforcementLevel") FROM stdin;
\.


--
-- Data for Name: secret_approval_policies_approvers; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_policies_approvers (id, "policyId", "createdAt", "updatedAt", "approverUserId", "approverGroupId") FROM stdin;
\.


--
-- Data for Name: secret_approval_request_secret_tags; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_request_secret_tags (id, "secretId", "tagId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_approval_request_secret_tags_v2; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_request_secret_tags_v2 (id, "secretId", "tagId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_approval_requests; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_requests (id, "policyId", "hasMerged", status, conflicts, slug, "folderId", "createdAt", "updatedAt", "isReplicated", "committerUserId", "statusChangedByUserId", "bypassReason") FROM stdin;
\.


--
-- Data for Name: secret_approval_requests_reviewers; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_requests_reviewers (id, status, "requestId", "createdAt", "updatedAt", "reviewerUserId") FROM stdin;
\.


--
-- Data for Name: secret_approval_requests_secrets; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_requests_secrets (id, version, "secretBlindIndex", "secretKeyCiphertext", "secretKeyIV", "secretKeyTag", "secretValueCiphertext", "secretValueIV", "secretValueTag", "secretCommentCiphertext", "secretCommentIV", "secretCommentTag", "secretReminderNote", "secretReminderRepeatDays", "skipMultilineEncoding", algorithm, "keyEncoding", metadata, "createdAt", "updatedAt", "requestId", op, "secretId", "secretVersion") FROM stdin;
\.


--
-- Data for Name: secret_approval_requests_secrets_v2; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_approval_requests_secrets_v2 (id, version, key, "encryptedValue", "encryptedComment", "reminderNote", "reminderRepeatDays", "skipMultilineEncoding", metadata, "createdAt", "updatedAt", "requestId", op, "secretId", "secretVersion") FROM stdin;
\.


--
-- Data for Name: secret_blind_indexes; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_blind_indexes (id, "encryptedSaltCipherText", "saltIV", "saltTag", algorithm, "keyEncoding", "projectId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_folder_versions; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_folder_versions (id, name, version, "createdAt", "updatedAt", "envId", "folderId") FROM stdin;
ac91b53a-2d01-4beb-b840-6983a7ce61c5	app	1	2025-10-22 15:40:04.858738+00	2025-10-22 15:40:04.858738+00	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f
667fce06-62f1-41c3-b6e7-32ba45ae0301	app	1	2025-10-22 15:40:04.868975+00	2025-10-22 15:40:04.868975+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d
68dc6735-f026-4732-99d0-427db3f8c645	app	1	2025-10-22 15:40:04.886926+00	2025-10-22 15:40:04.886926+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07
0fd8b2c9-f3ce-4912-bdaf-4607778d507c	be	1	2025-10-22 15:40:08.261474+00	2025-10-22 15:40:08.261474+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	18bb9dff-2f16-40d3-93e6-6d8e606f9a77
6f3a5688-9430-4ec9-9c9f-214dd948e4c4	be	1	2025-10-22 15:40:08.269368+00	2025-10-22 15:40:08.269368+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	580bbcd8-2935-468a-a6fa-9ad9d3398fe3
4e86a3e8-d1cc-441a-b33c-43794a03372b	be	1	2025-10-22 15:40:08.266932+00	2025-10-22 15:40:08.266932+00	31fcb5e1-23f2-4589-b779-167352214b1f	8fd3572b-38d8-4e8c-9d2f-98257fed9729
4d28ae8f-9c02-416f-a475-4788f82b7a46	core	1	2025-10-22 15:40:36.622184+00	2025-10-22 15:40:36.622184+00	31fcb5e1-23f2-4589-b779-167352214b1f	e1ae276b-68ce-4c00-89e8-5b4a1734760b
59ec78b9-1fef-4d02-809e-afc94655a953	core	1	2025-10-22 15:40:36.623752+00	2025-10-22 15:40:36.623752+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	a8e47cea-2024-4f7c-b1e0-fa69de68f888
b8e41720-a44f-4f6f-a5e3-5e5faf551b69	core	1	2025-10-22 15:40:36.636145+00	2025-10-22 15:40:36.636145+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d1d47cac-650b-438e-bee0-db8446b7a111
04b4a613-31b1-4924-89d1-df4d749daf66	has	1	2025-10-22 15:40:39.847981+00	2025-10-22 15:40:39.847981+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	3dd9d7bc-fdf4-44fa-8ebb-dd219f8572da
f3edeecc-337a-4f9e-a006-815cd75231a6	has	1	2025-10-22 15:40:39.855858+00	2025-10-22 15:40:39.855858+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	961c9a0f-4814-4132-96b0-1b0bafe011dc
e8df5b8b-b2b9-43e7-a760-65912e7a8a6c	has	1	2025-10-22 15:40:39.911769+00	2025-10-22 15:40:39.911769+00	31fcb5e1-23f2-4589-b779-167352214b1f	c3ef0b3c-de87-4d16-9a61-bf0cfe2155c2
86e472a4-cf0f-455f-8868-398b2be98ce8	his	1	2025-10-22 15:40:43.714902+00	2025-10-22 15:40:43.714902+00	31fcb5e1-23f2-4589-b779-167352214b1f	ce8ec9ce-7849-4c7a-9f67-630c20cbbc2f
6c6736fa-116f-4d3d-9a17-5efa32912200	his	1	2025-10-22 15:40:43.715679+00	2025-10-22 15:40:43.715679+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	d50c6e31-7a12-4856-a006-50ae65879180
660a0b43-34da-4039-b56f-8c51a4fae50c	his	1	2025-10-22 15:40:43.721057+00	2025-10-22 15:40:43.721057+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	26deaa68-ff6d-4b49-813f-a69dd264847b
edf96426-74a7-4d45-ac58-9b44718b7813	be	1	2025-10-22 15:42:26.118515+00	2025-10-22 15:42:26.118515+00	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce
2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	be	1	2025-10-22 15:42:26.12845+00	2025-10-22 15:42:26.12845+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a
d60d55c4-3b39-4efd-adcd-50371a89bd45	be	1	2025-10-22 15:42:26.144745+00	2025-10-22 15:42:26.144745+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699
a1bf94b4-ac9d-4a61-9984-3bab3a55498c	auth	1	2025-10-22 15:50:13.305548+00	2025-10-22 15:50:13.305548+00	31fcb5e1-23f2-4589-b779-167352214b1f	353ab2c4-06d9-4aae-95ee-52dbbdab42fa
b649780c-dc90-4107-a36e-72e3007137fc	auth	1	2025-10-22 15:50:13.30914+00	2025-10-22 15:50:13.30914+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	c9ccb3c6-d774-41fb-93b6-be2f4319470b
829f550a-37b2-4c11-97a4-28774437efa0	auth	1	2025-10-22 15:50:13.315175+00	2025-10-22 15:50:13.315175+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	0540f808-64a0-4782-953c-b41ede4f88a8
\.


--
-- Data for Name: secret_folders; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_folders (id, name, version, "createdAt", "updatedAt", "envId", "parentId", "isReserved") FROM stdin;
b3008a94-6937-43e8-ad16-74c17e9c18d5	root	1	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	\N	f
9a38b5d6-0b73-4e67-87b6-a80561ace832	root	1	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00	31fcb5e1-23f2-4589-b779-167352214b1f	\N	f
ee4196e1-ca5d-48d0-8dff-35475654cf98	root	1	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	\N	f
ffc0c4c3-5350-44ea-a573-0f99a532677f	app	1	2025-10-22 15:40:04.858738+00	2025-10-22 15:40:04.858738+00	31fcb5e1-23f2-4589-b779-167352214b1f	9a38b5d6-0b73-4e67-87b6-a80561ace832	f
bea88e16-53a2-478c-b653-4cf2349caf7d	app	1	2025-10-22 15:40:04.868975+00	2025-10-22 15:40:04.868975+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b3008a94-6937-43e8-ad16-74c17e9c18d5	f
43cf1568-8fc2-4401-819c-e62949351c07	app	1	2025-10-22 15:40:04.886926+00	2025-10-22 15:40:04.886926+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	ee4196e1-ca5d-48d0-8dff-35475654cf98	f
04c8a5bb-668a-4207-a189-3549854ddfce	be	1	2025-10-22 15:42:26.118515+00	2025-10-22 15:42:26.118515+00	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	f
2707578f-df91-451e-80b7-f2fc488e815a	be	1	2025-10-22 15:42:26.12845+00	2025-10-22 15:42:26.12845+00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	f
5bc6e6bb-7529-4395-abdf-bd66d0adb699	be	1	2025-10-22 15:42:26.144745+00	2025-10-22 15:42:26.144745+00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	f
8ae0e6fa-1c96-4b4e-a9c3-9f64c63f6ebe	root	1	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00	15a1dd97-f1d2-455f-8328-141644e1f032	\N	f
e4511410-f276-46e6-82bf-074363964703	root	1	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00	5eb8c92e-5aeb-4aa6-8615-13e8a3163a40	\N	f
05c2e293-0bfe-4acc-81cb-0b04ee0a5566	root	1	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00	24f31f48-cb28-4bb5-b231-8917e97559e6	\N	f
ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	root	1	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	\N	f
2060d386-1de0-4d43-bb57-ad4833fe317d	root	1	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	\N	f
7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	root	1	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00	3e8a705e-9742-43ea-96cb-89fe88aed058	\N	f
46346785-4314-4bd6-928f-e09d54847e98	root	1	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00	82732d9d-904b-4f60-bc34-dbd6dfd85b97	\N	f
ed0fa5be-f07b-4aeb-bddb-5068d048c889	root	1	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00	80af13d8-3dcd-41e6-9e1f-6932888266da	\N	f
0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	root	1	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00	1bbe551a-fa18-4df7-8897-2d15055d5c28	\N	f
df55f1e8-12b3-436c-84b4-270f7a54c1c2	root	1	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00	b62ee3ae-1ed9-478b-afb3-9a09473ba774	\N	f
94e67651-7c8f-4de7-b648-f9632e94ed99	root	1	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00	03ebf868-ea91-44d9-9dda-e328e13d3561	\N	f
a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	root	1	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00	6926a156-9533-45dc-bcb6-b716ab914f46	\N	f
dca4e684-c441-41fa-91d1-986fcbbf14c1	root	1	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00	aaf3c10b-93ec-44cb-9211-cbfc97c13ff3	\N	f
46b4244c-c2ce-45ec-891f-7dd38d86e753	root	1	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00	a8048ec8-1200-453e-b7cb-4a0dedb9eb89	\N	f
73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	root	1	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00	7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	\N	f
\.


--
-- Data for Name: secret_imports; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_imports (id, version, "importPath", "importEnv", "position", "createdAt", "updatedAt", "folderId", "isReplication", "isReplicationSuccess", "replicationStatus", "lastReplicated", "isReserved") FROM stdin;
\.


--
-- Data for Name: secret_references; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_references (id, environment, "secretPath", "secretId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_references_v2; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_references_v2 (id, environment, "secretPath", "secretKey", "secretId") FROM stdin;
\.


--
-- Data for Name: secret_rotation_output_v2; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_rotation_output_v2 (id, key, "secretId", "rotationId") FROM stdin;
\.


--
-- Data for Name: secret_rotation_outputs; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_rotation_outputs (id, key, "secretId", "rotationId") FROM stdin;
\.


--
-- Data for Name: secret_rotations; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_rotations (id, provider, "secretPath", "interval", "lastRotatedAt", status, "statusMessage", "encryptedData", "encryptedDataIV", "encryptedDataTag", algorithm, "keyEncoding", "envId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_scanning_git_risks; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_scanning_git_risks (id, description, "startLine", "endLine", "startColumn", "endColumn", file, "symlinkFile", commit, entropy, author, email, date, message, tags, "ruleID", fingerprint, "fingerPrintWithoutCommitId", "isFalsePositive", "isResolved", "riskOwner", "installationId", "repositoryId", "repositoryLink", "repositoryFullName", "pusherName", "pusherEmail", status, "orgId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_sharing; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_sharing (id, "encryptedValue", iv, tag, "hashedHex", "expiresAt", "userId", "orgId", "createdAt", "updatedAt", "expiresAfterViews", "accessType", name, "lastViewedAt", password, "encryptedSecret", identifier) FROM stdin;
\.


--
-- Data for Name: secret_snapshot_folders; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_snapshot_folders (id, "envId", "folderVersionId", "snapshotId", "createdAt", "updatedAt") FROM stdin;
cee092ef-9db5-466f-9410-c87a4d7e3e2c	31fcb5e1-23f2-4589-b779-167352214b1f	ac91b53a-2d01-4beb-b840-6983a7ce61c5	96bc2150-fe95-43e6-a478-597a7d9ae057	2025-10-22 15:40:04.880756+00	2025-10-22 15:40:04.880756+00
5779018a-785a-4a75-9d4e-3d7e2c15c3f1	a28ceab1-d6a2-404e-b21b-fb9a14194e65	667fce06-62f1-41c3-b6e7-32ba45ae0301	908a703e-e447-420b-8e65-32a55447cb75	2025-10-22 15:40:04.897563+00	2025-10-22 15:40:04.897563+00
926164d0-6fde-4a35-b511-9d4dda7df379	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	68dc6735-f026-4732-99d0-427db3f8c645	ec01c098-acb2-42af-8cfe-e10b3c1a1ad8	2025-10-22 15:40:04.921829+00	2025-10-22 15:40:04.921829+00
7abb5abd-ee39-4fbe-85cb-d0706260b536	a28ceab1-d6a2-404e-b21b-fb9a14194e65	667fce06-62f1-41c3-b6e7-32ba45ae0301	58504cbe-7c66-4529-83a8-bc7249cd3fc2	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
ff642e02-b577-4b1f-b869-515e94c07fcc	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0fd8b2c9-f3ce-4912-bdaf-4607778d507c	58504cbe-7c66-4529-83a8-bc7249cd3fc2	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
6b52daa6-f15d-4f99-94f7-b7496f0455c6	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	68dc6735-f026-4732-99d0-427db3f8c645	b8313e4b-fe31-44dd-adb3-cb7403d5c315	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
817621b9-e80f-4b56-ba00-ed57be578cdc	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	6f3a5688-9430-4ec9-9c9f-214dd948e4c4	b8313e4b-fe31-44dd-adb3-cb7403d5c315	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
5188d091-008e-42f0-9d3a-7ffe8e7816fd	31fcb5e1-23f2-4589-b779-167352214b1f	ac91b53a-2d01-4beb-b840-6983a7ce61c5	0271b03c-30d8-4968-a603-3396991f3a95	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
26a743e2-29f3-415a-a60d-d5912dfa7f08	31fcb5e1-23f2-4589-b779-167352214b1f	4e86a3e8-d1cc-441a-b33c-43794a03372b	0271b03c-30d8-4968-a603-3396991f3a95	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
dfaa3930-7544-439f-ad4b-f548d46565bc	31fcb5e1-23f2-4589-b779-167352214b1f	4d28ae8f-9c02-416f-a475-4788f82b7a46	e5544f2e-62b2-477f-9efb-b8da6cab6725	2025-10-22 15:40:36.643723+00	2025-10-22 15:40:36.643723+00
1d00f1bd-3b09-4228-89fb-aacc60ea1733	a28ceab1-d6a2-404e-b21b-fb9a14194e65	59ec78b9-1fef-4d02-809e-afc94655a953	e16f2e91-2a43-4ecf-8dda-490831c9a16c	2025-10-22 15:40:36.646511+00	2025-10-22 15:40:36.646511+00
adda09f2-8349-4678-b713-550ed891ffc5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b8e41720-a44f-4f6f-a5e3-5e5faf551b69	a020aaca-d36c-4b56-8543-53930406a194	2025-10-22 15:40:36.653355+00	2025-10-22 15:40:36.653355+00
17a391f6-56c4-40a6-b7fb-7ca1174b4ca0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	59ec78b9-1fef-4d02-809e-afc94655a953	08f8c54e-8875-4d54-9c6b-13b283c6d319	2025-10-22 15:40:39.886779+00	2025-10-22 15:40:39.886779+00
d5e16cbd-2b54-4379-b0b6-6758d9b4b53c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	04b4a613-31b1-4924-89d1-df4d749daf66	08f8c54e-8875-4d54-9c6b-13b283c6d319	2025-10-22 15:40:39.886779+00	2025-10-22 15:40:39.886779+00
5e1dee2e-01e4-4385-b519-505cde42d256	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b8e41720-a44f-4f6f-a5e3-5e5faf551b69	065e3bbb-15f4-40e8-92c8-bd52b002b0d3	2025-10-22 15:40:39.902174+00	2025-10-22 15:40:39.902174+00
0483847e-1641-48ed-a02e-d710fdde7b5f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3edeecc-337a-4f9e-a006-815cd75231a6	065e3bbb-15f4-40e8-92c8-bd52b002b0d3	2025-10-22 15:40:39.902174+00	2025-10-22 15:40:39.902174+00
e3064afd-70c5-4757-8605-36c38e1833cb	31fcb5e1-23f2-4589-b779-167352214b1f	4d28ae8f-9c02-416f-a475-4788f82b7a46	37687120-1af6-4650-bd57-012b764ad5d5	2025-10-22 15:40:39.943691+00	2025-10-22 15:40:39.943691+00
6f348e70-c2c1-41b5-97de-b33bdd7cc477	31fcb5e1-23f2-4589-b779-167352214b1f	e8df5b8b-b2b9-43e7-a760-65912e7a8a6c	37687120-1af6-4650-bd57-012b764ad5d5	2025-10-22 15:40:39.943691+00	2025-10-22 15:40:39.943691+00
74617577-0a6f-4423-b730-e832b2ae127a	a28ceab1-d6a2-404e-b21b-fb9a14194e65	59ec78b9-1fef-4d02-809e-afc94655a953	d23cd8ec-953d-4648-9540-ae8ef754c16a	2025-10-22 15:40:43.73544+00	2025-10-22 15:40:43.73544+00
18f74126-42a0-4f24-89ea-350a4197ab11	a28ceab1-d6a2-404e-b21b-fb9a14194e65	04b4a613-31b1-4924-89d1-df4d749daf66	d23cd8ec-953d-4648-9540-ae8ef754c16a	2025-10-22 15:40:43.73544+00	2025-10-22 15:40:43.73544+00
55691e02-85a5-475a-a6b0-abdc98fed08d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6c6736fa-116f-4d3d-9a17-5efa32912200	d23cd8ec-953d-4648-9540-ae8ef754c16a	2025-10-22 15:40:43.73544+00	2025-10-22 15:40:43.73544+00
f0c50e96-1eb6-498e-a2cd-e55b0fab9a70	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b8e41720-a44f-4f6f-a5e3-5e5faf551b69	d21a4aac-7263-442f-ace2-57613eeaf24d	2025-10-22 15:40:43.737499+00	2025-10-22 15:40:43.737499+00
162c4398-c156-4edd-a270-d22f6cbffe1b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3edeecc-337a-4f9e-a006-815cd75231a6	d21a4aac-7263-442f-ace2-57613eeaf24d	2025-10-22 15:40:43.737499+00	2025-10-22 15:40:43.737499+00
4936094b-66d8-4504-8146-49dcc010d5e9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	660a0b43-34da-4039-b56f-8c51a4fae50c	d21a4aac-7263-442f-ace2-57613eeaf24d	2025-10-22 15:40:43.737499+00	2025-10-22 15:40:43.737499+00
49ffd8e1-54af-4573-adcc-1d9a30f70e77	31fcb5e1-23f2-4589-b779-167352214b1f	4d28ae8f-9c02-416f-a475-4788f82b7a46	6b5ff9b5-2d9b-4f11-8f51-fed86c8abd7a	2025-10-22 15:40:43.733919+00	2025-10-22 15:40:43.733919+00
78e81238-7f14-4873-9abb-4fe08f823e3d	31fcb5e1-23f2-4589-b779-167352214b1f	e8df5b8b-b2b9-43e7-a760-65912e7a8a6c	6b5ff9b5-2d9b-4f11-8f51-fed86c8abd7a	2025-10-22 15:40:43.733919+00	2025-10-22 15:40:43.733919+00
85ab6c4f-00e7-4b03-86aa-8d12ef185bb2	31fcb5e1-23f2-4589-b779-167352214b1f	86e472a4-cf0f-455f-8868-398b2be98ce8	6b5ff9b5-2d9b-4f11-8f51-fed86c8abd7a	2025-10-22 15:40:43.733919+00	2025-10-22 15:40:43.733919+00
555971f9-3bcc-4e3c-bc69-a38dc6b24d24	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	f8ce7a58-e59c-4a65-9d32-3b382eb56ba3	2025-10-22 15:42:26.158735+00	2025-10-22 15:42:26.158735+00
91beb3e7-5da8-4e68-8568-93e96924f0d2	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	b28e3151-c34f-48c5-9ebc-57f95c0f2050	2025-10-22 15:42:56.362656+00	2025-10-22 15:42:56.362656+00
9a3bc7b5-98bd-426d-80d9-064bbd7885c9	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	6a06f20a-e51a-46cc-9158-48dc16b22d6c	2025-10-22 15:48:26.606235+00	2025-10-22 15:48:26.606235+00
68d23ea7-ad44-4393-9551-4fd538761392	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	9420dac8-bf23-4133-b428-9b10ea98d095	2025-10-22 15:48:27.02419+00	2025-10-22 15:48:27.02419+00
037cb8c2-da8b-4ee8-9e12-1ae1a5c383c2	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	57ef27db-a4f8-4c7f-9111-1f448c46b6e8	2025-10-22 15:48:35.032273+00	2025-10-22 15:48:35.032273+00
a59f5419-21aa-4200-8a67-2480da00561d	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	f2cd2594-1b55-4de4-ae32-5d8ab030f4a4	2025-10-22 15:48:35.557049+00	2025-10-22 15:48:35.557049+00
a97715ff-9ff6-4faf-8c2c-b769c33bd9e0	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	1cdecf28-bf7b-4400-8a9d-40e187210988	2025-10-22 15:48:43.226385+00	2025-10-22 15:48:43.226385+00
c5f4a166-1705-48ee-b74b-b1923eec8fe7	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	0a5ff89c-5e31-490c-a77e-2bdad892d003	2025-10-22 15:48:43.580855+00	2025-10-22 15:48:43.580855+00
1800464e-e9c8-42df-9024-3956400dbbd5	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	5952dc35-c15f-4132-ba89-9bfeb6652328	2025-10-22 15:48:51.234639+00	2025-10-22 15:48:51.234639+00
95b1d2e1-773c-4c0b-bec7-9d64f347e3d0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	efb07b17-4fc8-44c9-afb2-5b5a889696ee	2025-10-22 15:48:51.629027+00	2025-10-22 15:48:51.629027+00
d9a43f80-357e-4410-8c35-c80986ae391e	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	823131c6-8946-4de6-a3b1-699f43f4e4e1	2025-10-22 15:49:02.397456+00	2025-10-22 15:49:02.397456+00
26cc46f6-7da4-4deb-add3-233655557e16	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	d40bd981-9966-461b-b146-91678b54bec1	2025-10-22 15:49:02.771452+00	2025-10-22 15:49:02.771452+00
37e1ee30-fe32-4889-ab10-06d512aad27d	31fcb5e1-23f2-4589-b779-167352214b1f	a1bf94b4-ac9d-4a61-9984-3bab3a55498c	fd0ff6cb-e0e7-4404-9b36-19bfa11c9ca8	2025-10-22 15:50:13.320327+00	2025-10-22 15:50:13.320327+00
e3eb0d2a-ae34-442d-88d8-11f4ce64a31b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b649780c-dc90-4107-a36e-72e3007137fc	c54d1694-6719-44bc-b95c-a29940ef0a60	2025-10-22 15:50:13.332932+00	2025-10-22 15:50:13.332932+00
768f5d4f-9fb6-4450-ba4d-6f455d8d334c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	829f550a-37b2-4c11-97a4-28774437efa0	a4f5efcd-0746-4e2f-bee4-89ee46c82629	2025-10-22 15:50:13.335666+00	2025-10-22 15:50:13.335666+00
f11195bd-1f4d-4c7b-8945-2634fb8a58c2	31fcb5e1-23f2-4589-b779-167352214b1f	ac91b53a-2d01-4beb-b840-6983a7ce61c5	f6beecf7-815d-4597-a7bf-8ca9fdefaae9	2025-10-22 15:50:28.096783+00	2025-10-22 15:50:28.096783+00
8175bb2c-5e4a-445c-8476-95f8205b707f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	667fce06-62f1-41c3-b6e7-32ba45ae0301	31796b85-aa5b-44c3-af7d-682a0f3cf177	2025-10-22 15:50:28.199861+00	2025-10-22 15:50:28.199861+00
8c9a5539-9662-4e9b-8729-8c40a277f888	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	68dc6735-f026-4732-99d0-427db3f8c645	4d2d9e81-38ec-448b-9adc-ab137ae8440a	2025-10-22 15:50:28.230784+00	2025-10-22 15:50:28.230784+00
a4a2ffff-3f89-4b68-92cb-f3ab58c32d6e	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	3b6ac231-5108-4c85-9a1f-aa8ca5800a68	2025-10-22 19:08:40.3366+00	2025-10-22 19:08:40.3366+00
bdbaa627-a61c-4ba7-83c0-4c75f40d293c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	ce89aa13-825e-42e1-ac6a-48da442c4706	2025-10-22 19:08:40.388951+00	2025-10-22 19:08:40.388951+00
d1860052-a20b-4f56-b8f3-2ca1cdb428dd	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	c9eee93c-88cc-40d3-a31a-dd53b4575c69	2025-10-22 19:08:40.392052+00	2025-10-22 19:08:40.392052+00
7dfcaea8-1d3a-4ff9-929d-8173a249f4a1	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	eb5fe9ef-f761-462f-9da5-fa8107b7d62c	2025-10-23 17:35:42.485666+00	2025-10-23 17:35:42.485666+00
c8e3c2cf-544b-41ab-980b-5b157a561f26	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	7a509fd6-9a5e-46c3-90cd-e2eba74c3e99	2025-10-23 17:35:42.487945+00	2025-10-23 17:35:42.487945+00
c8e96d0f-e1a1-4832-84cc-62ee9c8fbbf0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	8ae86467-0613-4c2e-ab6f-61f177db297b	2025-10-23 17:35:42.571562+00	2025-10-23 17:35:42.571562+00
0924600a-33ba-4747-86c6-281b807d9830	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	70c0f88c-e064-4800-85f5-cf33bbe1a3f7	2025-10-23 17:35:57.182788+00	2025-10-23 17:35:57.182788+00
6bf414fe-2aed-40b4-9f3a-1c4e9794396c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	e9b37274-3573-46ed-bccb-dc3013a92ed5	2025-10-23 17:35:57.188359+00	2025-10-23 17:35:57.188359+00
d0da53c5-4b13-4742-b43e-433382bff4a1	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	9d7918df-d87b-4ce3-a987-205b8a955824	2025-10-23 17:35:57.200077+00	2025-10-23 17:35:57.200077+00
35decb46-7bf4-492e-a970-25eeb58384d1	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	05963048-42aa-45ad-8413-37b5427f9a4c	2025-11-13 19:48:58.130416+00	2025-11-13 19:48:58.130416+00
f03ecd88-19a9-42c6-a2d3-ec05130c8bbe	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	0ea4a46a-ce0f-4f01-8af1-02de0ddcc0c5	2025-11-13 19:48:58.157749+00	2025-11-13 19:48:58.157749+00
89019b02-fe9a-49b1-9f1e-71919121318e	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	ac175104-e7cd-44c6-a18b-be800f1f1b3f	2025-11-13 19:48:58.165122+00	2025-11-13 19:48:58.165122+00
8507ddc0-a617-410c-8b3d-5e1ce34afae3	31fcb5e1-23f2-4589-b779-167352214b1f	edf96426-74a7-4d45-ac58-9b44718b7813	76e98719-8de2-44ad-bde6-c8757dd9b2f4	2025-11-13 19:49:18.788304+00	2025-11-13 19:49:18.788304+00
7eb10e3a-1823-418d-84d8-abc232f180f0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2302dcb4-30c3-4adc-a91d-d28f54b6e5b4	458986f7-3a58-4cf0-aea8-fc49e5685343	2025-11-13 19:49:18.816499+00	2025-11-13 19:49:18.816499+00
c6cfe98e-b35a-45f3-abc8-863d1aaf6c53	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d60d55c4-3b39-4efd-adcd-50371a89bd45	4fed09b4-e4b6-4125-82b3-ae8d70d764fd	2025-11-13 19:49:18.823565+00	2025-11-13 19:49:18.823565+00
\.


--
-- Data for Name: secret_snapshot_secrets; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_snapshot_secrets (id, "envId", "secretVersionId", "snapshotId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_snapshot_secrets_v2; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_snapshot_secrets_v2 (id, "envId", "secretVersionId", "snapshotId", "createdAt", "updatedAt") FROM stdin;
6550c661-6b3a-4480-a75a-bdb2448c8591	a28ceab1-d6a2-404e-b21b-fb9a14194e65	abd33f1c-be70-4ddf-8bc2-d9e338f1c14a	a33b7588-920a-4d76-85d1-2212953a84ad	2025-10-22 15:38:23.477548+00	2025-10-22 15:38:23.477548+00
d7e151b2-a7b3-40d6-9257-700daafcb819	a28ceab1-d6a2-404e-b21b-fb9a14194e65	387d5ef6-850d-4da3-b717-3cc65dc142da	a33b7588-920a-4d76-85d1-2212953a84ad	2025-10-22 15:38:23.477548+00	2025-10-22 15:38:23.477548+00
822df4c4-d0d4-4387-b93b-f1d60630fa9a	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b85b891c-3ea5-4dee-8091-60c1357c3822	a33b7588-920a-4d76-85d1-2212953a84ad	2025-10-22 15:38:23.477548+00	2025-10-22 15:38:23.477548+00
57965f08-1497-43bd-a0b0-609c31034dcd	a28ceab1-d6a2-404e-b21b-fb9a14194e65	77372a79-e256-4ac9-a760-13785626be60	a33b7588-920a-4d76-85d1-2212953a84ad	2025-10-22 15:38:23.477548+00	2025-10-22 15:38:23.477548+00
d6e22f5e-3c47-451c-bb37-ef130d49c259	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bd295f12-e92a-409a-889c-1ce3eb6eaba2	a33b7588-920a-4d76-85d1-2212953a84ad	2025-10-22 15:38:23.477548+00	2025-10-22 15:38:23.477548+00
dc749dc8-4cb6-4954-a317-3938c053758c	31fcb5e1-23f2-4589-b779-167352214b1f	2b42f712-516f-4cb6-8224-361b45ae8c1a	26850928-66f3-40bc-9fe7-c64434257208	2025-10-22 15:38:58.218459+00	2025-10-22 15:38:58.218459+00
81599c5f-0a67-44ad-8460-4fb3f387519a	31fcb5e1-23f2-4589-b779-167352214b1f	581165fd-156c-4976-80c9-628c178a4166	26850928-66f3-40bc-9fe7-c64434257208	2025-10-22 15:38:58.218459+00	2025-10-22 15:38:58.218459+00
4708396c-cbdb-42c6-b4c2-e51c0586383e	31fcb5e1-23f2-4589-b779-167352214b1f	9843681e-a644-40fc-b3f7-15f53a99fe14	26850928-66f3-40bc-9fe7-c64434257208	2025-10-22 15:38:58.218459+00	2025-10-22 15:38:58.218459+00
75245eed-bbe2-4ac7-98fd-b8e664f37628	31fcb5e1-23f2-4589-b779-167352214b1f	7570897c-27d2-4957-912e-fcda9f9d0e54	26850928-66f3-40bc-9fe7-c64434257208	2025-10-22 15:38:58.218459+00	2025-10-22 15:38:58.218459+00
8c5087d2-0f09-4e90-93e3-58d2376b56fb	31fcb5e1-23f2-4589-b779-167352214b1f	16c23d3f-a7f3-46fc-bbd8-f8758e319914	26850928-66f3-40bc-9fe7-c64434257208	2025-10-22 15:38:58.218459+00	2025-10-22 15:38:58.218459+00
733d2e9e-63d3-4f8c-a1da-83ce8b7e5c8c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	bd087604-a9ac-4bce-8f5f-a4108fefbf7a	e7cd9f89-63b0-43da-ab0c-7dbf4bad0855	2025-10-22 15:39:15.77807+00	2025-10-22 15:39:15.77807+00
106aa826-86e6-4f76-bf53-bfa40fe74722	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	040491d1-4b80-4762-a691-9abb9fef6242	e7cd9f89-63b0-43da-ab0c-7dbf4bad0855	2025-10-22 15:39:15.77807+00	2025-10-22 15:39:15.77807+00
781573c2-109b-40cb-b94c-eb3a1d1c3457	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	edd47d6e-9e20-430f-94be-728f163e73f8	e7cd9f89-63b0-43da-ab0c-7dbf4bad0855	2025-10-22 15:39:15.77807+00	2025-10-22 15:39:15.77807+00
2cdb8ab2-c648-4d2d-9c35-d2a8f5b26369	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	10747c25-787d-4d2c-b333-4c1b75c59330	e7cd9f89-63b0-43da-ab0c-7dbf4bad0855	2025-10-22 15:39:15.77807+00	2025-10-22 15:39:15.77807+00
5952ffc8-afad-4fdd-8a52-2b44d410fcff	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	45da988b-0c76-4dbc-9b18-5407c1dbfba2	e7cd9f89-63b0-43da-ab0c-7dbf4bad0855	2025-10-22 15:39:15.77807+00	2025-10-22 15:39:15.77807+00
dbad2dd2-c449-41e6-8e7c-4a8300e9ee3c	31fcb5e1-23f2-4589-b779-167352214b1f	2b42f712-516f-4cb6-8224-361b45ae8c1a	96bc2150-fe95-43e6-a478-597a7d9ae057	2025-10-22 15:40:04.880756+00	2025-10-22 15:40:04.880756+00
c4bdc2d0-6bd7-4479-8c5a-0aa0e754e222	31fcb5e1-23f2-4589-b779-167352214b1f	581165fd-156c-4976-80c9-628c178a4166	96bc2150-fe95-43e6-a478-597a7d9ae057	2025-10-22 15:40:04.880756+00	2025-10-22 15:40:04.880756+00
7e2c1c3f-ccf6-4315-aad9-e5722b8b80b3	31fcb5e1-23f2-4589-b779-167352214b1f	9843681e-a644-40fc-b3f7-15f53a99fe14	96bc2150-fe95-43e6-a478-597a7d9ae057	2025-10-22 15:40:04.880756+00	2025-10-22 15:40:04.880756+00
1eeb0a35-f0d8-4127-991f-7f92d1b2109b	31fcb5e1-23f2-4589-b779-167352214b1f	7570897c-27d2-4957-912e-fcda9f9d0e54	96bc2150-fe95-43e6-a478-597a7d9ae057	2025-10-22 15:40:04.880756+00	2025-10-22 15:40:04.880756+00
2b179e81-e2a0-42b8-8baa-ec23bfcec9c2	31fcb5e1-23f2-4589-b779-167352214b1f	16c23d3f-a7f3-46fc-bbd8-f8758e319914	96bc2150-fe95-43e6-a478-597a7d9ae057	2025-10-22 15:40:04.880756+00	2025-10-22 15:40:04.880756+00
ec7947ec-d0e7-46c5-bf47-336a03ee9549	a28ceab1-d6a2-404e-b21b-fb9a14194e65	abd33f1c-be70-4ddf-8bc2-d9e338f1c14a	908a703e-e447-420b-8e65-32a55447cb75	2025-10-22 15:40:04.897563+00	2025-10-22 15:40:04.897563+00
cadf25ff-d1b4-42f5-b7a2-ed5ab4d3763e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	387d5ef6-850d-4da3-b717-3cc65dc142da	908a703e-e447-420b-8e65-32a55447cb75	2025-10-22 15:40:04.897563+00	2025-10-22 15:40:04.897563+00
c8d95e21-5cc5-47c7-b4c8-0ad98094a448	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b85b891c-3ea5-4dee-8091-60c1357c3822	908a703e-e447-420b-8e65-32a55447cb75	2025-10-22 15:40:04.897563+00	2025-10-22 15:40:04.897563+00
4c32b327-c38c-4b0d-a2d9-65482cf2b75d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	77372a79-e256-4ac9-a760-13785626be60	908a703e-e447-420b-8e65-32a55447cb75	2025-10-22 15:40:04.897563+00	2025-10-22 15:40:04.897563+00
02fe82da-4864-434b-8ab4-a50a25cf928c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bd295f12-e92a-409a-889c-1ce3eb6eaba2	908a703e-e447-420b-8e65-32a55447cb75	2025-10-22 15:40:04.897563+00	2025-10-22 15:40:04.897563+00
01ca9602-ece0-443b-a270-5bfb2192c4b0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	bd087604-a9ac-4bce-8f5f-a4108fefbf7a	ec01c098-acb2-42af-8cfe-e10b3c1a1ad8	2025-10-22 15:40:04.921829+00	2025-10-22 15:40:04.921829+00
96c52f9c-2ec5-4cfe-970d-e426087f9fde	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	040491d1-4b80-4762-a691-9abb9fef6242	ec01c098-acb2-42af-8cfe-e10b3c1a1ad8	2025-10-22 15:40:04.921829+00	2025-10-22 15:40:04.921829+00
cb3d6723-e1cb-4d1f-a738-cc0d1c56a6c1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	edd47d6e-9e20-430f-94be-728f163e73f8	ec01c098-acb2-42af-8cfe-e10b3c1a1ad8	2025-10-22 15:40:04.921829+00	2025-10-22 15:40:04.921829+00
cf8164ca-5b9a-40fc-be13-4c60c844a13b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	10747c25-787d-4d2c-b333-4c1b75c59330	ec01c098-acb2-42af-8cfe-e10b3c1a1ad8	2025-10-22 15:40:04.921829+00	2025-10-22 15:40:04.921829+00
d64f8e30-2615-40f5-adeb-a50842b3dbb2	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	45da988b-0c76-4dbc-9b18-5407c1dbfba2	ec01c098-acb2-42af-8cfe-e10b3c1a1ad8	2025-10-22 15:40:04.921829+00	2025-10-22 15:40:04.921829+00
fca8c2b7-494b-402c-9e01-e918d77ca720	a28ceab1-d6a2-404e-b21b-fb9a14194e65	abd33f1c-be70-4ddf-8bc2-d9e338f1c14a	58504cbe-7c66-4529-83a8-bc7249cd3fc2	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
ef9238de-4f79-4afc-b835-c2290a94d6aa	a28ceab1-d6a2-404e-b21b-fb9a14194e65	387d5ef6-850d-4da3-b717-3cc65dc142da	58504cbe-7c66-4529-83a8-bc7249cd3fc2	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
bde40ecd-5c7b-4d8b-8eaf-125c253fcd33	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b85b891c-3ea5-4dee-8091-60c1357c3822	58504cbe-7c66-4529-83a8-bc7249cd3fc2	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
1dede08a-c7db-470c-8af8-48fd37a34f8f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	77372a79-e256-4ac9-a760-13785626be60	58504cbe-7c66-4529-83a8-bc7249cd3fc2	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
171477ee-cab1-48a9-b810-34e126571b09	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bd295f12-e92a-409a-889c-1ce3eb6eaba2	58504cbe-7c66-4529-83a8-bc7249cd3fc2	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
42efbbad-2018-43ba-9841-208cb8b4ae06	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	bd087604-a9ac-4bce-8f5f-a4108fefbf7a	b8313e4b-fe31-44dd-adb3-cb7403d5c315	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
b7eeefd9-ef8c-4d58-9757-25a9abca86c5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	040491d1-4b80-4762-a691-9abb9fef6242	b8313e4b-fe31-44dd-adb3-cb7403d5c315	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
549d491c-4ebc-48cd-8969-e7289b863c14	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	edd47d6e-9e20-430f-94be-728f163e73f8	b8313e4b-fe31-44dd-adb3-cb7403d5c315	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
c06191ca-b0b1-4fa0-9970-2424d450fb9a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	10747c25-787d-4d2c-b333-4c1b75c59330	b8313e4b-fe31-44dd-adb3-cb7403d5c315	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
4eaf0895-2f08-4d6f-b92b-82de81e9b8ca	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	45da988b-0c76-4dbc-9b18-5407c1dbfba2	b8313e4b-fe31-44dd-adb3-cb7403d5c315	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
a647fddd-3638-4977-9205-eba446f407d4	31fcb5e1-23f2-4589-b779-167352214b1f	2b42f712-516f-4cb6-8224-361b45ae8c1a	0271b03c-30d8-4968-a603-3396991f3a95	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
5aa59c9a-ed2e-41ca-8925-0a462773f6db	31fcb5e1-23f2-4589-b779-167352214b1f	581165fd-156c-4976-80c9-628c178a4166	0271b03c-30d8-4968-a603-3396991f3a95	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
1b91fac5-ccc7-4257-acb9-a560516a082c	31fcb5e1-23f2-4589-b779-167352214b1f	9843681e-a644-40fc-b3f7-15f53a99fe14	0271b03c-30d8-4968-a603-3396991f3a95	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
42064792-84f5-44db-b5c8-3f1df3371466	31fcb5e1-23f2-4589-b779-167352214b1f	7570897c-27d2-4957-912e-fcda9f9d0e54	0271b03c-30d8-4968-a603-3396991f3a95	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
adf5d42c-44c5-44b0-ad0e-3d26e12adfe4	31fcb5e1-23f2-4589-b779-167352214b1f	16c23d3f-a7f3-46fc-bbd8-f8758e319914	0271b03c-30d8-4968-a603-3396991f3a95	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
30bff47a-378c-497a-88ac-dac9189e0ff1	5eb8c92e-5aeb-4aa6-8615-13e8a3163a40	f38033cc-64e3-4697-b87c-c3639736f113	06eb20dc-be63-4ba5-ae8e-c4547fe3f2e9	2025-11-11 19:17:13.570561+00	2025-11-11 19:17:13.570561+00
8d1ee4a3-6ec1-4fa2-9d05-769880b5b997	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
742b7acc-83b3-4f90-b096-cc133506c9b4	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
47560db3-2e59-47b4-8655-673dd907c627	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
d93e5e23-1c09-4167-b558-4e60cde59285	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
9923ba91-06d5-4f1f-9279-f9baab219691	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
2f3d5e22-15ef-499d-b74e-bdf61d89f841	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
02c86871-c397-49ca-bc37-c0ae1c76df40	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
48e4c8f5-4165-4cbc-9233-66ab2d964ecd	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
37af9706-6b75-4991-bfc7-1c4b29657675	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
9e8c6e7d-86fb-4ab0-8a90-9ee40e29152a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
54f5930f-d67d-4130-bbda-1a01a9435393	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
49959b37-c7db-4d7c-836e-062ced7e0200	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
ee7d9673-3b3a-48f9-b4d6-8924fc91756f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
8b96cde8-2ff9-4639-bc9a-d47e5dec0712	24f31f48-cb28-4bb5-b231-8917e97559e6	729a9abd-5173-4dd6-afa7-77827ce58f8a	69e761be-2d5d-4bd0-abb9-96cf3783fbb0	2025-11-11 19:17:13.575587+00	2025-11-11 19:17:13.575587+00
03505e81-2adc-45ae-bcf3-0fbb941a9a63	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
29d14fc0-83da-43ff-b324-06add0fd1aa0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
cf677a64-c764-4cfa-8ea4-15df1770b55b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
9a428040-d702-483c-afe5-ad6ecb7a9538	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
634fa3fc-7b06-4092-a381-4e2fe962bd32	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	9906114e-2eee-4dc3-a9de-1aff750dfa9c	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
0ffcfebd-bc08-4008-8a86-2f33392b6f68	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bf40fb9-9c63-4bf4-ad3d-04b54a76b388	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
56b51cb6-cfff-45bf-9158-7dc328194705	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	790d025b-75be-454b-b929-99a030355692	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
0def96b8-10b6-4b5f-b876-a170e8321bfb	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	8a30f366-a7a8-444a-8cf6-ec9c7104efa0	7af1d203-b0b5-45a6-bc16-5da8ccb3a807	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
05b5f6ae-55ab-4808-8529-eab41b030d32	3e8a705e-9742-43ea-96cb-89fe88aed058	79c6d6c2-a968-48ac-9a5b-66b725a594c0	aa8af915-85be-40cd-b55b-104c032c7240	2025-12-08 18:39:54.492089+00	2025-12-08 18:39:54.492089+00
6d7bac18-1fcc-42c4-b185-c145287a173a	3e8a705e-9742-43ea-96cb-89fe88aed058	0861f48e-08cc-4766-94c9-06ca4a322544	aa8af915-85be-40cd-b55b-104c032c7240	2025-12-08 18:39:54.492089+00	2025-12-08 18:39:54.492089+00
7f44e1b6-6b66-4440-ad6c-7d307ea7f8be	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c8e940ae-9816-4b6d-8453-bac9c2722f4b	502ee93a-8303-46c7-9eec-5e6a777c83e9	2025-12-08 18:41:13.427666+00	2025-12-08 18:41:13.427666+00
62f9fcca-6529-408f-b2e1-7cfca32d743a	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c14ce8af-ff97-4250-b218-c33f0badc492	502ee93a-8303-46c7-9eec-5e6a777c83e9	2025-12-08 18:41:13.427666+00	2025-12-08 18:41:13.427666+00
6cc7ab54-8641-4da2-bc58-0abc81852e09	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	b54233b5-9d8a-4f92-a4b1-3a244a3ae148	502ee93a-8303-46c7-9eec-5e6a777c83e9	2025-12-08 18:41:13.427666+00	2025-12-08 18:41:13.427666+00
ef6e050f-5e23-4bbd-b29c-c39d5e6279d7	3e8a705e-9742-43ea-96cb-89fe88aed058	76c88ea3-2fca-4c0b-a35a-119e17788de3	d90a5199-e375-4c6b-b672-a43204d0c37a	2025-12-08 18:41:56.185757+00	2025-12-08 18:41:56.185757+00
a6796db8-35c7-43e8-98a0-a11abb3ba466	3e8a705e-9742-43ea-96cb-89fe88aed058	17a4a454-7b0d-4d52-94a0-87250f35b5a1	d90a5199-e375-4c6b-b672-a43204d0c37a	2025-12-08 18:41:56.185757+00	2025-12-08 18:41:56.185757+00
43b6b787-f80f-4136-bfcb-3906b67440cd	3e8a705e-9742-43ea-96cb-89fe88aed058	0861f48e-08cc-4766-94c9-06ca4a322544	d90a5199-e375-4c6b-b672-a43204d0c37a	2025-12-08 18:41:56.185757+00	2025-12-08 18:41:56.185757+00
e9cb2aa7-e950-4b49-93b1-040659d0db79	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	64bb8b9f-bf6a-4b0a-99e6-e2bdf2911b5a	cdf6bda8-0e29-4af5-9844-0789dc399868	2025-12-08 19:08:16.993941+00	2025-12-08 19:08:16.993941+00
93c4163a-cebb-4d67-b6da-688f14aee158	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	faf61269-33ac-45d2-a3ce-53dcdd44f399	cdf6bda8-0e29-4af5-9844-0789dc399868	2025-12-08 19:08:16.993941+00	2025-12-08 19:08:16.993941+00
7cb432e9-ca2c-4869-af0d-bd7c3dfbfcac	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	b54233b5-9d8a-4f92-a4b1-3a244a3ae148	cdf6bda8-0e29-4af5-9844-0789dc399868	2025-12-08 19:08:16.993941+00	2025-12-08 19:08:16.993941+00
0785abaf-0a02-41fc-a837-e78f42b01e03	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c2d2fcc1-8c5d-4490-8a8b-1cac7ca419cf	cdf6bda8-0e29-4af5-9844-0789dc399868	2025-12-08 19:08:16.993941+00	2025-12-08 19:08:16.993941+00
c5283d69-4acc-4dd8-af19-80238257ed6d	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	64bb8b9f-bf6a-4b0a-99e6-e2bdf2911b5a	108a71a1-162e-417c-be7c-95e466cd6aae	2025-12-08 19:08:25.244484+00	2025-12-08 19:08:25.244484+00
afa7b615-ae4a-4044-a156-c8f211c15a66	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	faf61269-33ac-45d2-a3ce-53dcdd44f399	108a71a1-162e-417c-be7c-95e466cd6aae	2025-12-08 19:08:25.244484+00	2025-12-08 19:08:25.244484+00
8b9a0610-b182-41a9-8359-a03670c8a7f0	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	725db5ca-8cea-43fd-8194-f7e6dcb25a3a	108a71a1-162e-417c-be7c-95e466cd6aae	2025-12-08 19:08:25.244484+00	2025-12-08 19:08:25.244484+00
fdf1b3f1-8f03-461f-9a8b-da200fc6f7d8	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c2d2fcc1-8c5d-4490-8a8b-1cac7ca419cf	108a71a1-162e-417c-be7c-95e466cd6aae	2025-12-08 19:08:25.244484+00	2025-12-08 19:08:25.244484+00
bbd1d3ce-9a42-4d5d-a326-07fcc6d32f93	3e8a705e-9742-43ea-96cb-89fe88aed058	ffc5c0fe-cc56-479f-b177-b236212b5280	437a735c-6fd6-4690-a99e-f9c60a84f8ad	2025-12-08 19:08:31.755334+00	2025-12-08 19:08:31.755334+00
ffd7208a-3946-493c-a275-babba5d7f05f	3e8a705e-9742-43ea-96cb-89fe88aed058	36a0c9ff-1dea-4a8e-8f0b-0c9891b8b409	437a735c-6fd6-4690-a99e-f9c60a84f8ad	2025-12-08 19:08:31.755334+00	2025-12-08 19:08:31.755334+00
0064216b-ad32-4b4a-adb3-d24749c85f44	3e8a705e-9742-43ea-96cb-89fe88aed058	17a4a454-7b0d-4d52-94a0-87250f35b5a1	437a735c-6fd6-4690-a99e-f9c60a84f8ad	2025-12-08 19:08:31.755334+00	2025-12-08 19:08:31.755334+00
ed928066-edb3-4e74-b734-9d22435e8b33	3e8a705e-9742-43ea-96cb-89fe88aed058	535d5be4-58ce-442a-95e4-4d0a1a8221b4	437a735c-6fd6-4690-a99e-f9c60a84f8ad	2025-12-08 19:08:31.755334+00	2025-12-08 19:08:31.755334+00
5513ed89-fcfd-4b22-a329-4d0a14d6817a	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	64bb8b9f-bf6a-4b0a-99e6-e2bdf2911b5a	eaa7e540-3890-41ac-861f-66c4771b4adc	2025-12-08 19:08:41.636896+00	2025-12-08 19:08:41.636896+00
be0299f8-a826-4099-838f-8b6c06a3dcb6	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	0bdc3061-5c21-4402-af22-c65166f963c1	eaa7e540-3890-41ac-861f-66c4771b4adc	2025-12-08 19:08:41.636896+00	2025-12-08 19:08:41.636896+00
1ec9be8b-5904-430e-87ce-81aabbc5571f	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	725db5ca-8cea-43fd-8194-f7e6dcb25a3a	eaa7e540-3890-41ac-861f-66c4771b4adc	2025-12-08 19:08:41.636896+00	2025-12-08 19:08:41.636896+00
5cd5a6de-b77b-416b-99cb-09c08a5c8662	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c4dd691e-8d35-4498-90f8-7641a4dcc1c8	eaa7e540-3890-41ac-861f-66c4771b4adc	2025-12-08 19:08:41.636896+00	2025-12-08 19:08:41.636896+00
04652288-fb1e-4067-afec-c7b6a653b899	80af13d8-3dcd-41e6-9e1f-6932888266da	0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	e9622930-b80d-402b-8bd1-0e5928c466a5	2025-12-10 16:48:15.145414+00	2025-12-10 16:48:15.145414+00
25daeec6-cdf1-41e9-b9e7-c267b363ea4c	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	e9622930-b80d-402b-8bd1-0e5928c466a5	2025-12-10 16:48:15.145414+00	2025-12-10 16:48:15.145414+00
0902fe62-00e8-49f2-ab3f-26c9ed9e1700	80af13d8-3dcd-41e6-9e1f-6932888266da	0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	f654f316-8ac5-4679-8d05-747c5a4148f1	2025-12-10 16:48:41.897174+00	2025-12-10 16:48:41.897174+00
07869888-eec6-4c39-919d-58159b0209ce	80af13d8-3dcd-41e6-9e1f-6932888266da	fa97540a-9bbb-4da5-9f23-754cc9319db4	f654f316-8ac5-4679-8d05-747c5a4148f1	2025-12-10 16:48:41.897174+00	2025-12-10 16:48:41.897174+00
66661691-fb59-4361-8ab9-99a72fd8f929	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	f654f316-8ac5-4679-8d05-747c5a4148f1	2025-12-10 16:48:41.897174+00	2025-12-10 16:48:41.897174+00
a29f13e0-7657-40d4-a42f-7bda5114449d	80af13d8-3dcd-41e6-9e1f-6932888266da	e39f6223-5b4e-4818-940a-50a527a53b2a	c400b21c-4b83-414c-9d74-9fa7732068fe	2025-12-10 16:48:51.24781+00	2025-12-10 16:48:51.24781+00
81d2eab2-abce-434a-87fa-350b5102c956	80af13d8-3dcd-41e6-9e1f-6932888266da	0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	c400b21c-4b83-414c-9d74-9fa7732068fe	2025-12-10 16:48:51.24781+00	2025-12-10 16:48:51.24781+00
1620a90b-450b-4626-a5bd-c9a39368c64f	80af13d8-3dcd-41e6-9e1f-6932888266da	fa97540a-9bbb-4da5-9f23-754cc9319db4	c400b21c-4b83-414c-9d74-9fa7732068fe	2025-12-10 16:48:51.24781+00	2025-12-10 16:48:51.24781+00
ee7af267-b17a-4676-be51-c025217046c6	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	c400b21c-4b83-414c-9d74-9fa7732068fe	2025-12-10 16:48:51.24781+00	2025-12-10 16:48:51.24781+00
3e98dc71-58a9-4fdd-b9aa-619f2c51bad1	1bbe551a-fa18-4df7-8897-2d15055d5c28	89b1ad59-364f-4325-9c4b-81005dfdb883	28727c55-fa95-4cd3-90c9-3f0ad1733202	2025-12-10 16:48:51.253088+00	2025-12-10 16:48:51.253088+00
f5905087-9b47-4a5d-8150-f4db8d5dc1f3	1bbe551a-fa18-4df7-8897-2d15055d5c28	7fbe9247-d309-4dd9-977e-ac7c4a0bb1da	28727c55-fa95-4cd3-90c9-3f0ad1733202	2025-12-10 16:48:51.253088+00	2025-12-10 16:48:51.253088+00
7db57fba-3afd-43ed-9833-4f232ba91e25	1bbe551a-fa18-4df7-8897-2d15055d5c28	181da39c-f05b-492e-a911-62350fb24c5c	28727c55-fa95-4cd3-90c9-3f0ad1733202	2025-12-10 16:48:51.253088+00	2025-12-10 16:48:51.253088+00
8cdc59c7-e7cb-426d-b7a1-b2a4345febc3	1bbe551a-fa18-4df7-8897-2d15055d5c28	266a6184-9cd4-489f-a486-d0463304c90b	28727c55-fa95-4cd3-90c9-3f0ad1733202	2025-12-10 16:48:51.253088+00	2025-12-10 16:48:51.253088+00
fd7d40fe-d88a-499d-8eb7-f11a22041932	82732d9d-904b-4f60-bc34-dbd6dfd85b97	d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	6402a1ce-5cc8-42e0-a3f2-20b33440d76d	2025-12-10 16:49:03.479122+00	2025-12-10 16:49:03.479122+00
cb3f2124-0ad1-432a-9857-83c6d0e6c9b5	1bbe551a-fa18-4df7-8897-2d15055d5c28	89b1ad59-364f-4325-9c4b-81005dfdb883	b103586f-6355-4fa2-85d2-36725965b745	2025-12-10 16:49:03.480265+00	2025-12-10 16:49:03.480265+00
140cf850-6f62-4173-bf8e-a02115d8d73e	1bbe551a-fa18-4df7-8897-2d15055d5c28	7fbe9247-d309-4dd9-977e-ac7c4a0bb1da	b103586f-6355-4fa2-85d2-36725965b745	2025-12-10 16:49:03.480265+00	2025-12-10 16:49:03.480265+00
a595738c-0729-4544-af05-9724da7fc5c7	1bbe551a-fa18-4df7-8897-2d15055d5c28	ae7ccb0e-4f73-4236-a69a-075ae99b1de7	b103586f-6355-4fa2-85d2-36725965b745	2025-12-10 16:49:03.480265+00	2025-12-10 16:49:03.480265+00
0c6ff2ba-a2c5-421c-a057-b474d9f7a397	1bbe551a-fa18-4df7-8897-2d15055d5c28	181da39c-f05b-492e-a911-62350fb24c5c	b103586f-6355-4fa2-85d2-36725965b745	2025-12-10 16:49:03.480265+00	2025-12-10 16:49:03.480265+00
376457a0-6487-4a7b-9425-8853dd6acb30	1bbe551a-fa18-4df7-8897-2d15055d5c28	266a6184-9cd4-489f-a486-d0463304c90b	b103586f-6355-4fa2-85d2-36725965b745	2025-12-10 16:49:03.480265+00	2025-12-10 16:49:03.480265+00
ee1d17e3-bc05-4123-ab3e-4cbce4d6de1a	80af13d8-3dcd-41e6-9e1f-6932888266da	18063347-1b0e-4b21-b458-15c32b0bf751	e2884f3d-cadc-4b44-993c-ddf1d85bf58d	2025-12-10 16:49:03.487099+00	2025-12-10 16:49:03.487099+00
6f5f4595-e251-4dd4-84f7-49af56a8c29b	80af13d8-3dcd-41e6-9e1f-6932888266da	e39f6223-5b4e-4818-940a-50a527a53b2a	e2884f3d-cadc-4b44-993c-ddf1d85bf58d	2025-12-10 16:49:03.487099+00	2025-12-10 16:49:03.487099+00
329ba37f-19d7-4834-8c78-d8e487b679fd	80af13d8-3dcd-41e6-9e1f-6932888266da	0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	e2884f3d-cadc-4b44-993c-ddf1d85bf58d	2025-12-10 16:49:03.487099+00	2025-12-10 16:49:03.487099+00
c1c93c3d-a06e-44b6-accd-b85932bdb711	80af13d8-3dcd-41e6-9e1f-6932888266da	fa97540a-9bbb-4da5-9f23-754cc9319db4	e2884f3d-cadc-4b44-993c-ddf1d85bf58d	2025-12-10 16:49:03.487099+00	2025-12-10 16:49:03.487099+00
048b8a93-fb99-4b12-8cb9-e6a67c496cc4	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	e2884f3d-cadc-4b44-993c-ddf1d85bf58d	2025-12-10 16:49:03.487099+00	2025-12-10 16:49:03.487099+00
0c3420ad-e808-49c9-ad56-695795d7f518	15a1dd97-f1d2-455f-8328-141644e1f032	0d3abf37-e63e-4af7-ad40-9eefec29770f	0c0ae51e-5c02-421e-9a49-2dc8b0a22901	2025-11-11 19:17:13.57747+00	2025-11-11 19:17:13.57747+00
e73f44c8-9646-4917-811e-63c1da00a9c0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
fc751bac-96a0-4d76-bcb3-c47349aa6579	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
07d6b12d-16f0-4c3a-bc63-462ed2f0ed64	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
791abfae-d190-4756-bef3-82d075a8872f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
d923c893-ddd0-431f-bbb8-f8d5cbe27d66	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
dc45db50-ab74-4a2b-a5b6-fcf3dd61d64e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
75417087-0a09-4279-a7ee-b13db16e3be8	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
6d7f0da6-48a6-4e55-b70a-d9ed8f062d7b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
cbf94d32-06f3-4c59-8c47-d096461115ee	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
0633351e-c525-4058-97ac-354056545471	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
e2f809b3-0f4c-40ab-b453-9cbf5baa6f7a	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
ad756613-a579-4ef1-8252-aa609185b037	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
62a95689-0307-4904-bdfe-43d224c2f651	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
312dcbe3-814a-46b2-bbcd-c1a021a74357	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
98fa641c-efbc-41e7-ad48-90f16c0c4f46	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
c1f68dcd-1cd8-47aa-a33e-988a50cb0c29	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
31d20d0e-4058-4bd3-9af9-25c52bf35d82	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
de67bee6-70bf-4f76-bf98-c8d40d786e00	a28ceab1-d6a2-404e-b21b-fb9a14194e65	41b7a346-3ed8-4af2-9110-62d90f492343	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
4f6d07f2-680c-439c-a4c9-f7dd06b534bc	a28ceab1-d6a2-404e-b21b-fb9a14194e65	059a3f39-a329-4d81-a1bc-a5077ebc741a	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
c6d9beb6-0b95-4107-b6a2-6705b651e518	a28ceab1-d6a2-404e-b21b-fb9a14194e65	245b6b90-dce1-4d39-958e-cda5790e3bb2	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
a000b4fc-08f5-43ba-b2da-659f2638e9b4	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f72a55a5-9acf-4f63-9b84-d8f98a77a528	3bdae9f7-1a81-467d-8eaa-f1061d1199f5	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
bda08b19-b187-46a8-8cb6-dd5bdceaa6cc	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	1fec7905-8299-42ac-8092-b308a0dfac31	309cc460-870c-4f46-a031-edd41d05b9a0	2025-12-08 18:14:21.85834+00	2025-12-08 18:14:21.85834+00
a161c8e4-67b5-4cb0-ad36-d5071d6ceaa3	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	5c9adfa1-cd6c-4f5e-8522-c4edb8cc8883	309cc460-870c-4f46-a031-edd41d05b9a0	2025-12-08 18:14:21.85834+00	2025-12-08 18:14:21.85834+00
3c0fbb25-6679-4c18-967b-b100b7960475	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	709918a8-a0b3-4656-86d6-c7dc5aa1190b	309cc460-870c-4f46-a031-edd41d05b9a0	2025-12-08 18:14:21.85834+00	2025-12-08 18:14:21.85834+00
35ce1e73-d517-4dc7-865c-5d8a57956784	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c1873b43-e68a-4507-82a4-9ba52cc678e8	309cc460-870c-4f46-a031-edd41d05b9a0	2025-12-08 18:14:21.85834+00	2025-12-08 18:14:21.85834+00
fc9b7731-4c46-4214-ad78-63a6d9680e03	3e8a705e-9742-43ea-96cb-89fe88aed058	6e021572-c7df-48eb-9665-92302406fb55	6e355de3-2069-464e-9791-fa6b22d63537	2025-12-08 18:14:25.323718+00	2025-12-08 18:14:25.323718+00
dd0dc262-4e41-4db6-a017-9dd62d27d64c	3e8a705e-9742-43ea-96cb-89fe88aed058	565d5c08-2f10-4fe6-a364-bdd43b0f1fec	6e355de3-2069-464e-9791-fa6b22d63537	2025-12-08 18:14:25.323718+00	2025-12-08 18:14:25.323718+00
91915294-3a8c-4f2c-89de-d1f5389fda09	3e8a705e-9742-43ea-96cb-89fe88aed058	09354fff-dc5a-4766-92bc-1d507df014fe	6e355de3-2069-464e-9791-fa6b22d63537	2025-12-08 18:14:25.323718+00	2025-12-08 18:14:25.323718+00
65366db3-532c-40cb-9cab-4db37707ee4d	3e8a705e-9742-43ea-96cb-89fe88aed058	0861f48e-08cc-4766-94c9-06ca4a322544	6e355de3-2069-464e-9791-fa6b22d63537	2025-12-08 18:14:25.323718+00	2025-12-08 18:14:25.323718+00
37a1b475-63de-4710-a724-942e91a28353	3e8a705e-9742-43ea-96cb-89fe88aed058	76c88ea3-2fca-4c0b-a35a-119e17788de3	e288278f-f024-4392-ad2c-c38cfe99ce87	2025-12-08 18:41:13.446342+00	2025-12-08 18:41:13.446342+00
3933249a-e7bd-40bf-bd88-6756905f3035	3e8a705e-9742-43ea-96cb-89fe88aed058	79c6d6c2-a968-48ac-9a5b-66b725a594c0	e288278f-f024-4392-ad2c-c38cfe99ce87	2025-12-08 18:41:13.446342+00	2025-12-08 18:41:13.446342+00
f56ebb51-5585-4465-a79a-d6be8c23bb2b	3e8a705e-9742-43ea-96cb-89fe88aed058	0861f48e-08cc-4766-94c9-06ca4a322544	e288278f-f024-4392-ad2c-c38cfe99ce87	2025-12-08 18:41:13.446342+00	2025-12-08 18:41:13.446342+00
d645424a-0696-4b3e-ad9b-af35944d73e7	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	3020a48b-073f-4d49-873a-426ced18f547	fdd66c3c-f5dc-4a02-a95c-544b3f2e7a9a	2025-12-08 18:42:07.092213+00	2025-12-08 18:42:07.092213+00
8231ef91-8458-4a78-adb4-7cc902d909cd	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c9e1a973-830e-411f-ac29-277d19290304	fdd66c3c-f5dc-4a02-a95c-544b3f2e7a9a	2025-12-08 18:42:07.092213+00	2025-12-08 18:42:07.092213+00
fd3a5a70-451d-48e7-a1bb-eae41d365b01	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	709918a8-a0b3-4656-86d6-c7dc5aa1190b	fdd66c3c-f5dc-4a02-a95c-544b3f2e7a9a	2025-12-08 18:42:07.092213+00	2025-12-08 18:42:07.092213+00
b29cf57f-354e-480b-a810-ea7d85156cd9	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c6d872cc-254d-4eb3-be3d-28eb87105d9d	fdd66c3c-f5dc-4a02-a95c-544b3f2e7a9a	2025-12-08 18:42:07.092213+00	2025-12-08 18:42:07.092213+00
198f1876-b0cc-4fcb-a5f2-f49dd8adae73	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c8e940ae-9816-4b6d-8453-bac9c2722f4b	d543c567-aa5f-4d1d-adc3-d8d546c8131f	2025-12-08 18:42:07.110935+00	2025-12-08 18:42:07.110935+00
c9023d2f-e20d-4af5-90ed-fb8dc5d606fb	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	faf61269-33ac-45d2-a3ce-53dcdd44f399	d543c567-aa5f-4d1d-adc3-d8d546c8131f	2025-12-08 18:42:07.110935+00	2025-12-08 18:42:07.110935+00
dc7099f2-b7b5-4378-a532-3cb2085c59a5	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	b54233b5-9d8a-4f92-a4b1-3a244a3ae148	d543c567-aa5f-4d1d-adc3-d8d546c8131f	2025-12-08 18:42:07.110935+00	2025-12-08 18:42:07.110935+00
c8741533-b032-485f-aa1e-c10fcde8ac04	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c2d2fcc1-8c5d-4490-8a8b-1cac7ca419cf	d543c567-aa5f-4d1d-adc3-d8d546c8131f	2025-12-08 18:42:07.110935+00	2025-12-08 18:42:07.110935+00
9f1aa43d-4f4b-4ac1-a7f6-e0c78ff6eaba	3e8a705e-9742-43ea-96cb-89fe88aed058	76c88ea3-2fca-4c0b-a35a-119e17788de3	72e0e25e-ec7c-4e2a-980b-daa0fa30b4a2	2025-12-08 19:08:17.018353+00	2025-12-08 19:08:17.018353+00
ad7ced99-61dd-496b-8763-038d7069a3a8	3e8a705e-9742-43ea-96cb-89fe88aed058	749acc37-2329-4330-9254-b73ee803f56e	72e0e25e-ec7c-4e2a-980b-daa0fa30b4a2	2025-12-08 19:08:17.018353+00	2025-12-08 19:08:17.018353+00
6fcf131c-0a34-453b-8c0a-4f4b49bf8aed	3e8a705e-9742-43ea-96cb-89fe88aed058	17a4a454-7b0d-4d52-94a0-87250f35b5a1	72e0e25e-ec7c-4e2a-980b-daa0fa30b4a2	2025-12-08 19:08:17.018353+00	2025-12-08 19:08:17.018353+00
9238b847-bfe9-49a2-85c8-da1ebe2c100c	3e8a705e-9742-43ea-96cb-89fe88aed058	535d5be4-58ce-442a-95e4-4d0a1a8221b4	72e0e25e-ec7c-4e2a-980b-daa0fa30b4a2	2025-12-08 19:08:17.018353+00	2025-12-08 19:08:17.018353+00
ffb19ec1-29b3-41f4-a38f-1a83b72c08b1	3e8a705e-9742-43ea-96cb-89fe88aed058	ffc5c0fe-cc56-479f-b177-b236212b5280	fabf95ec-df86-43ab-89c2-1f1a28da028a	2025-12-08 19:08:25.248671+00	2025-12-08 19:08:25.248671+00
679f05e8-6b6c-42d1-8f2f-3d1aa29da882	3e8a705e-9742-43ea-96cb-89fe88aed058	749acc37-2329-4330-9254-b73ee803f56e	fabf95ec-df86-43ab-89c2-1f1a28da028a	2025-12-08 19:08:25.248671+00	2025-12-08 19:08:25.248671+00
ccdc6f0e-eedf-45ce-928a-38fc73493827	3e8a705e-9742-43ea-96cb-89fe88aed058	17a4a454-7b0d-4d52-94a0-87250f35b5a1	fabf95ec-df86-43ab-89c2-1f1a28da028a	2025-12-08 19:08:25.248671+00	2025-12-08 19:08:25.248671+00
5c1058a9-bcbc-44eb-9778-b4e12d19973c	3e8a705e-9742-43ea-96cb-89fe88aed058	535d5be4-58ce-442a-95e4-4d0a1a8221b4	fabf95ec-df86-43ab-89c2-1f1a28da028a	2025-12-08 19:08:25.248671+00	2025-12-08 19:08:25.248671+00
c88f6e38-0ccd-470f-a757-c238623bb70f	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	64bb8b9f-bf6a-4b0a-99e6-e2bdf2911b5a	658c7443-60ad-4b3f-88a5-54dd3f96d7c5	2025-12-08 19:08:31.758304+00	2025-12-08 19:08:31.758304+00
d47eda23-f6e4-4ef6-82b5-051edb3b3786	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	faf61269-33ac-45d2-a3ce-53dcdd44f399	658c7443-60ad-4b3f-88a5-54dd3f96d7c5	2025-12-08 19:08:31.758304+00	2025-12-08 19:08:31.758304+00
0bb643db-c9a1-43e9-b0cb-ca239bf0263d	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	725db5ca-8cea-43fd-8194-f7e6dcb25a3a	658c7443-60ad-4b3f-88a5-54dd3f96d7c5	2025-12-08 19:08:31.758304+00	2025-12-08 19:08:31.758304+00
1f9e6888-36b9-4bab-a5c2-cc5f7a8687b0	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c4dd691e-8d35-4498-90f8-7641a4dcc1c8	658c7443-60ad-4b3f-88a5-54dd3f96d7c5	2025-12-08 19:08:31.758304+00	2025-12-08 19:08:31.758304+00
6da47e8c-7372-46f5-9cb0-1e0dfa46561e	3e8a705e-9742-43ea-96cb-89fe88aed058	ffc5c0fe-cc56-479f-b177-b236212b5280	7c777bcf-fbfa-4668-b7bc-cab04e2b7988	2025-12-08 19:08:41.639564+00	2025-12-08 19:08:41.639564+00
e1b6b408-173c-4f24-b0c3-85f5bc4c6644	3e8a705e-9742-43ea-96cb-89fe88aed058	36a0c9ff-1dea-4a8e-8f0b-0c9891b8b409	7c777bcf-fbfa-4668-b7bc-cab04e2b7988	2025-12-08 19:08:41.639564+00	2025-12-08 19:08:41.639564+00
d01fa533-dee5-4721-a6a2-c2fceffb727e	3e8a705e-9742-43ea-96cb-89fe88aed058	65c1dfce-4d2b-40b6-9558-72f255d9a323	7c777bcf-fbfa-4668-b7bc-cab04e2b7988	2025-12-08 19:08:41.639564+00	2025-12-08 19:08:41.639564+00
2efdbc9e-2e98-4d3c-8883-413c3a2e9371	3e8a705e-9742-43ea-96cb-89fe88aed058	535d5be4-58ce-442a-95e4-4d0a1a8221b4	7c777bcf-fbfa-4668-b7bc-cab04e2b7988	2025-12-08 19:08:41.639564+00	2025-12-08 19:08:41.639564+00
7752675c-3f1f-4b36-82b3-18003bbbd5e5	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	cd7b30cd-27a2-4041-b9a1-38e93e9314c1	2025-12-10 16:48:15.125983+00	2025-12-10 16:48:15.125983+00
07317c83-a48c-441a-ad8f-c4ef3a9ee463	82732d9d-904b-4f60-bc34-dbd6dfd85b97	d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	cd7b30cd-27a2-4041-b9a1-38e93e9314c1	2025-12-10 16:48:15.125983+00	2025-12-10 16:48:15.125983+00
afdb7c5f-72b2-4e0d-a4d7-d92be030a5b2	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
f77094ca-39ae-4a6b-8fb9-c6308f59d325	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
6b2b8c6f-125c-4a38-be1a-daa260afd8d7	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
431511f1-b8d2-4cf5-aa63-12636cedbcd4	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
355cfd39-7d88-4e5d-a48a-9eaecb3d4075	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
33c3ae70-9d7c-4018-8797-bd783c22d002	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
175cc020-b02c-4fe6-9075-2504b26ba8e8	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
764a1b74-fe98-46f3-8c41-56d3ad41894e	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
5a391e5f-ca74-4565-8925-8934ec2150f7	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
58676612-92a8-4c44-97dc-fd46df353023	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
08f719ff-690b-47a6-b9dd-7e3fa15e51cc	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
56efa82d-435f-4efb-a573-ffcc76281cd1	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
aa767ee1-76e0-4165-8080-da1de68c097e	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
8ba2efcc-1848-4869-a0dc-6fa97a3e1e2c	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
ad003a99-b4b7-4883-9dcd-fffdfc9cd36b	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
2ec40ef8-6b0c-4e65-881f-20bbf3bd8906	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
140e1079-7d50-4a29-952e-6f2ad081651d	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
c0e8fa97-b4fa-49ed-9150-13492581ae7f	31fcb5e1-23f2-4589-b779-167352214b1f	2652386b-b7d7-41d8-ab9f-22e3a2e0357d	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
096544b7-c64a-415c-9f6a-0cd4db0ca547	31fcb5e1-23f2-4589-b779-167352214b1f	c3c5cba3-9ea3-4561-8d45-86170d045b3c	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
0a930900-6009-428f-aa41-1e90f8f95c8d	31fcb5e1-23f2-4589-b779-167352214b1f	9f6f671b-8447-4c15-ad9e-a46c1460d3e0	37f71a2a-ce5b-42d1-973f-144aac126ca7	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
626dd3e5-549a-4e1e-944f-312f26458462	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
5e7ba417-ebeb-49c6-adbc-029e9c65c1f7	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
4a678e5a-5618-41b1-a5da-bb50e8493f59	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	9906114e-2eee-4dc3-a9de-1aff750dfa9c	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
c402d5a4-e767-4cb5-aa48-0f91e41fd4e7	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
e11a5611-7249-4b41-b43e-ff7c116dbd90	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
e2114829-0a87-40c3-bb82-4a2c355b532b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
c0a975fc-42e0-49dc-9e02-d622390af405	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
fcdecd20-bc5f-4510-a247-48e74e46e148	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
2bed7ffe-c09d-4248-9bca-da7ed8d8afaf	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
15694f7d-3793-453e-923d-9b068ab4f8f9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
513a5063-a87f-4420-a78b-766424b79c3d	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
3d8b1dc8-5a6d-4609-8cff-abb37254fc17	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bf40fb9-9c63-4bf4-ad3d-04b54a76b388	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
af9ef948-a2b4-4cb2-8c5a-dfa46478bb8c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
cdc57e5c-9e55-4de6-8257-cc08e16a67d3	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
44e2c1c8-dd85-43d1-a22d-a159c2cb91b2	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
aad498e2-143b-46da-80c1-6ed5c6f49344	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	790d025b-75be-454b-b929-99a030355692	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
9b9c80ba-0a52-49ba-8121-49c81236d34a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
5f141781-2241-46ff-8d07-2b503e003711	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
1b5a3a3e-824e-4634-a06c-ef7e88f93149	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
486d47fc-bb8a-42be-bd15-d58de1bec6ab	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	830cdde6-2924-4b7e-a12f-94e20d72f2bc	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
7a76a2ad-8b9c-4578-9571-bcedda929554	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	2d583463-e828-4f3f-8cee-84c597b1a7e2	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
4f79aead-186c-4439-b0ce-f642b4a3062e	31fcb5e1-23f2-4589-b779-167352214b1f	2b42f712-516f-4cb6-8224-361b45ae8c1a	f6beecf7-815d-4597-a7bf-8ca9fdefaae9	2025-10-22 15:50:28.096783+00	2025-10-22 15:50:28.096783+00
552fa447-30ea-404c-998b-b8686d63417c	31fcb5e1-23f2-4589-b779-167352214b1f	9843681e-a644-40fc-b3f7-15f53a99fe14	f6beecf7-815d-4597-a7bf-8ca9fdefaae9	2025-10-22 15:50:28.096783+00	2025-10-22 15:50:28.096783+00
491e712b-7eac-4acf-9342-01fe8f0d4eb9	31fcb5e1-23f2-4589-b779-167352214b1f	7570897c-27d2-4957-912e-fcda9f9d0e54	f6beecf7-815d-4597-a7bf-8ca9fdefaae9	2025-10-22 15:50:28.096783+00	2025-10-22 15:50:28.096783+00
dd1b274d-aab6-4f5a-b6e6-1483dd370b05	31fcb5e1-23f2-4589-b779-167352214b1f	581165fd-156c-4976-80c9-628c178a4166	f6beecf7-815d-4597-a7bf-8ca9fdefaae9	2025-10-22 15:50:28.096783+00	2025-10-22 15:50:28.096783+00
3be6a6c3-dd42-4dc8-bfba-274131d1e6c5	31fcb5e1-23f2-4589-b779-167352214b1f	16c23d3f-a7f3-46fc-bbd8-f8758e319914	f6beecf7-815d-4597-a7bf-8ca9fdefaae9	2025-10-22 15:50:28.096783+00	2025-10-22 15:50:28.096783+00
f9a442fd-31f2-4d45-9dd7-282cd95111ef	a28ceab1-d6a2-404e-b21b-fb9a14194e65	abd33f1c-be70-4ddf-8bc2-d9e338f1c14a	31796b85-aa5b-44c3-af7d-682a0f3cf177	2025-10-22 15:50:28.199861+00	2025-10-22 15:50:28.199861+00
91402852-a738-45b0-952c-6f5b5676d2ed	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b85b891c-3ea5-4dee-8091-60c1357c3822	31796b85-aa5b-44c3-af7d-682a0f3cf177	2025-10-22 15:50:28.199861+00	2025-10-22 15:50:28.199861+00
84790ea4-f341-4f3a-9d93-b106fe991540	a28ceab1-d6a2-404e-b21b-fb9a14194e65	77372a79-e256-4ac9-a760-13785626be60	31796b85-aa5b-44c3-af7d-682a0f3cf177	2025-10-22 15:50:28.199861+00	2025-10-22 15:50:28.199861+00
0c273121-3e0d-47a7-a1f0-0d50090c5458	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bd295f12-e92a-409a-889c-1ce3eb6eaba2	31796b85-aa5b-44c3-af7d-682a0f3cf177	2025-10-22 15:50:28.199861+00	2025-10-22 15:50:28.199861+00
b8e9d9d5-f8a7-4216-8729-4e967dd5e098	a28ceab1-d6a2-404e-b21b-fb9a14194e65	387d5ef6-850d-4da3-b717-3cc65dc142da	31796b85-aa5b-44c3-af7d-682a0f3cf177	2025-10-22 15:50:28.199861+00	2025-10-22 15:50:28.199861+00
09c619c5-2c15-420a-a177-da2b7854b7ce	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	040491d1-4b80-4762-a691-9abb9fef6242	4d2d9e81-38ec-448b-9adc-ab137ae8440a	2025-10-22 15:50:28.230784+00	2025-10-22 15:50:28.230784+00
13186cea-1f98-4c24-8b6a-0d9112f38ba2	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	edd47d6e-9e20-430f-94be-728f163e73f8	4d2d9e81-38ec-448b-9adc-ab137ae8440a	2025-10-22 15:50:28.230784+00	2025-10-22 15:50:28.230784+00
c34c7282-0918-4f3b-9a29-c0eb1ff7885c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	45da988b-0c76-4dbc-9b18-5407c1dbfba2	4d2d9e81-38ec-448b-9adc-ab137ae8440a	2025-10-22 15:50:28.230784+00	2025-10-22 15:50:28.230784+00
347a4ee6-1fe2-42a1-85c7-faa779c67aea	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	bd087604-a9ac-4bce-8f5f-a4108fefbf7a	4d2d9e81-38ec-448b-9adc-ab137ae8440a	2025-10-22 15:50:28.230784+00	2025-10-22 15:50:28.230784+00
baef002c-5a81-4dc5-aba0-deb4a330059b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	10747c25-787d-4d2c-b333-4c1b75c59330	4d2d9e81-38ec-448b-9adc-ab137ae8440a	2025-10-22 15:50:28.230784+00	2025-10-22 15:50:28.230784+00
17ee2cc9-1ffd-4116-a402-9e2c06ef72c5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
ace0c6a5-09bb-4fef-b227-bdc7a2352c59	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
1493855e-aacf-417c-9a52-d5ec496c4243	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
1f67fcec-0334-432b-9eb5-afabd19b9609	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
c77a404f-f4bd-4cc1-9f65-de18d99b834b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
1ec31cc2-e29d-4e0e-893f-56d0f463fafe	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
f09ddbcb-cc66-4e71-b2be-5f34a1918c4e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
19f07eff-8202-49c1-bf18-ab59df25bd0e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
c0b6520e-a8af-4219-8649-3c7c5141cfd0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
e34d06ce-4c67-4dc7-a863-1651cffb2b0d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
27523705-297e-45d1-9d1e-a1ed31ad2f6f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
7fbf3c1c-cd1f-4174-9c73-adeff5ccc90b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
4d1d138b-61d8-4ab5-b394-916bd01d856c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
52a433f5-add2-4bd0-8147-6626b9d35562	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
b6ff61cf-7f12-4af0-9fe1-621c6d5ec7c0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
bfe78fa7-7eaa-48ff-b9ce-f8d3e37ecbcc	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
8f693ef1-9122-48b8-9337-17552793b0ec	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
2f0be36a-2a3e-4f40-ac3c-28d3fc859110	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
5efecad5-d164-4020-8566-b31e3e0d4059	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
887b9656-960e-49df-9b3d-f486f691a959	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
dc34caac-3d18-47d6-b6c0-45c3bfce22a7	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
308e1e3d-f6ed-4d4a-b783-410672112762	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
3be0f53c-c1f8-45f4-bf3e-b6fc2848bd3a	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
60972165-ada0-4181-b92c-801bc402a63c	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
ceb92d3e-71cb-44b6-a556-8bb9f6f73474	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
99c32c8f-ea88-42b3-9b94-4388e7dbe746	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
91c2f3f3-c2a0-44c1-b7d9-818ab7358bfc	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
959786b8-3f24-48b1-8da8-d98faed6cd59	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
625bf867-e34c-43b9-8697-a48a5f5e3770	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
c65e55dc-5032-4782-b9e7-677f4411f0f1	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
75715a1f-5e41-43b1-8abf-90f9e59f0de0	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
52a50977-7029-429b-a909-2ba124d41355	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
8993a248-e32a-450d-a438-30de97516eb8	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
fe03fdef-d631-4629-a441-d2f2a3388a77	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	34e575ff-4cee-4d18-8cb9-c732c9461a6d	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
3924f3ab-5f7f-4e2d-9de8-1201254863fa	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
cdd4601a-c657-46cd-9512-1059a6b413ba	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
1d2211aa-2f93-46d4-9c52-5eb4aa57cf63	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
1af6cb9c-c634-4a73-9e49-8b82d6ee6462	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
3490653e-fcb1-4265-8034-4bda82b12889	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
2ab30963-29a6-42fc-82b3-127724698f7a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
9067cd08-adfd-4877-a57c-148cc36b442b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
b42feb28-0117-4937-8606-c9b89629c6af	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
15802d9d-4d63-4a02-a8cd-3b82181b4fa5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
378d18ee-9008-4ed5-8de6-892c784a9fe4	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
d19014f1-91c3-4a5d-809a-e97cdc118058	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
dc939ac2-65b5-471a-aff4-57e26b31bcee	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
5d39b35b-ec68-4b2e-99ea-453a9607aaa0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
c00110b9-5aa0-481d-a5cd-e4a975aeabbf	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
cab0d903-6e34-4df7-9fa6-a4a00f1c770e	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
5928d219-969d-4287-8192-e84d9a9a403c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
77edc1ac-92db-4c88-8592-81ac58a2cae8	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
c88476fe-36b4-4e5d-9547-bbfb4a65bd89	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
ab235c81-1b19-4121-90f1-a371346e0b89	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
4bd8a926-df30-4c45-b667-57ae0ed0fb6a	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
daa0335c-bc2a-4e7e-bd73-c1e88191c2a1	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
24941a19-f1dd-4d27-8c15-6d54aa525f48	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
9b954d6d-7c04-48ac-af85-88df99b86119	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
1363597a-bd6c-4293-9882-9d676988ba1c	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
8c0d3378-b76f-4d5c-a295-71ee25da632a	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
6fe2b9cf-0a40-4c6e-a79f-60413ded16bf	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
cea30fb2-d7e5-4b8a-bb8f-842a0cf78be0	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
88fda7e1-62ba-4504-aa2f-417696faf0d7	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
bd752d21-ccd1-4c40-990e-ac77d831f2e5	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
296f2639-9aa2-4cd5-869d-35294ba86496	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
31c1d74b-82d0-4cd4-8802-ac2950013a35	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
94aed6ea-82ec-42b9-b8a3-898d503305fa	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
5e9f1395-11b5-476e-ae6a-57a9b7b0236f	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
2ad5d99e-532e-440d-8ead-9e0eb0f25211	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
1d490642-3bc1-4c7a-8eec-d07f1b3f875b	31fcb5e1-23f2-4589-b779-167352214b1f	7188dbfb-d2f9-4d2e-8bc9-6b94b001a7dd	c56b1432-7397-4973-a5f9-1301b14a0801	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
2935a6a9-a51b-4b80-a384-94bbe26087ae	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
34a0c819-caf4-4b8d-bee9-9f82944ca73c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
e11aa9f7-6396-4021-b191-6e06e4b4c9d2	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
9a0c5e0b-1dba-4871-9630-4f329dd771e1	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
6e29c2b6-ef1f-4888-b1d7-47fdb1a14ef9	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
2d95b31d-21bd-4b8b-98ed-16b863b1d036	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
25bb1062-663b-409e-b3f7-41a6f8b43dc7	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
e82b7444-8b1a-4c73-9ef6-a4b55732e68f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
673f8d6a-2da6-41aa-9d5b-c896a74bd563	a28ceab1-d6a2-404e-b21b-fb9a14194e65	958183ef-1358-4745-94ec-6d72b11ff7e6	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
5d448412-e2eb-4b3b-9215-72f367612a3f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
14c18541-b861-4897-a19f-46d86e874b72	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
faa21b24-65aa-4220-a61f-eadbc057e54e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
628cc43b-1a51-42b0-a8f7-de22e8ba729b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
48b26cbb-07a7-4ade-882e-1e15b876a0a4	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
af718bcc-1323-4eba-8628-a418f4e69556	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
d3bd7212-af80-4db4-892d-9af72a4d367b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
2d0defc1-d440-4e65-b6db-54e09198f829	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
aa6b1df9-8ad8-4cc6-a4ca-cc66709bad21	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	a08baf2e-5b44-4033-bab5-249171a8b649	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
ea37b72e-e0a1-4d27-b462-ca5e54ff7fc2	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
185d6281-5498-44d4-a583-3be063786e14	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
2ab3b3fc-f814-447d-b276-2f00a140335b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	0855c644-c225-4635-b34a-fc4abc291236	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
c162cad6-3b58-4236-a7d5-bba9c9377574	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
5ebe93df-412e-4436-a4ad-d28ec2e450b1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
129b6dd8-ac71-4597-8bda-f320a85e15af	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
c09e953c-c559-4ecf-87da-c05d7ad253b1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
06c4d622-88d8-40f6-8382-1ad3759c86df	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
9c55c191-effa-4041-82d8-4d2ef5628602	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
eeac0c1d-550e-4a5f-b67d-a8ebc5f18b4a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
91a496c9-3ea6-4778-b385-d9cae1bae40a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
90bbac59-f12d-41ce-86ae-645df37f2de9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
e691d683-1190-4750-9509-0bde64e271b1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
5920972b-066e-4706-94a4-159cf14a2caa	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
3a18a898-21fc-4310-abd0-20a73bd8f021	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
e1545ffb-3f0c-4df4-a183-c0c061374d43	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
4eb6e3a9-2f73-469c-b073-4e5efcbe5a9e	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
6f457f27-95b4-49b9-9d08-2ba6b8a071ba	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	0924bede-d2bf-4767-b728-fc9017264a7d	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
eb81014d-358e-4650-95cc-1241a5f2c2c6	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
45faa66b-74df-4d9e-91cb-ca8d9ec674e2	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
b8ee750d-fc80-45df-82d2-74c8108aa2d4	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	0855c644-c225-4635-b34a-fc4abc291236	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
cd40fd81-0416-4e71-8688-5ca2b199d13f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
e4e53bda-dbc7-4b9b-95ca-640574f3fd94	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
4c71a491-ea37-4ace-8fcb-43584b111e52	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
9ef2af91-d45f-4f29-929e-4d38d69a757c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
f749fb10-2d94-4a16-99bc-e681e7e9dd78	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
af3fd053-803a-45d4-aebd-38b6e408d983	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
f196d005-f9be-4de4-9197-5c680de2f925	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
4dbfa04a-1ac4-43d2-bbea-0fbf78b5157c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
d7cdf9ce-a76b-4411-a1dd-057bcafcaf85	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	45ab2fd7-a5a1-475e-b544-152d6720df33	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
5e5f5e86-0c07-4cd1-8698-e4d9c961e725	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
f9a6a191-1327-4fc0-9cdf-deb560f6a64a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
f419ef52-74ec-4686-9976-6b01d33096ca	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
1672796a-e987-4d10-a400-3a1a1f8af93c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
51cd5d98-13f6-4466-ad7f-14a5ac657c91	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
6dfca607-8a0f-457e-b9b6-1dca18dd1f79	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
823b7855-a5a3-452d-a51f-86ead93285a1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	f7890219-4be3-4a85-bbc9-43c918d021b1	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
ac654001-5465-42fc-9590-8c7657f0ed77	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
6f16ccea-f41d-4c54-b522-f10208cbff3d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
b2056abf-05dd-41ef-a1f2-86a7d0448271	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
ded0b30b-9312-46ff-828f-521bc5f1b562	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
3fa6793f-bc8e-4ca9-b1ec-71533bd660f8	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
d09e7428-1b16-4f83-b5be-b0f87c1f3d5c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
6c63f7ff-834c-4c3b-9c6c-bebf3e8bdfc2	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
5c684184-3ef6-4a03-b367-7c06fab730cd	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
06ad0c27-6b6a-4b80-87b0-a603fa6ee113	a28ceab1-d6a2-404e-b21b-fb9a14194e65	958183ef-1358-4745-94ec-6d72b11ff7e6	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
4eaa6935-1ebc-426d-a691-f1f5669f1ad2	a28ceab1-d6a2-404e-b21b-fb9a14194e65	e84ad97b-a61b-46f0-9cdd-523006f542eb	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
ef6e7347-730c-4e80-ab12-9aa0b9e39d30	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
bb37d12a-c281-4175-a539-5d58a9dffb0a	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
f1ae7317-7ef4-4f91-8ebc-16f80a3edebb	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
135e71ae-fea9-470e-ba30-73143104617b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
0b8a51b0-463f-4238-bcd5-151744d271c6	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
d6c358e1-25d2-4bf5-af0b-1d6c10f8bfbf	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
7d52d9d4-c077-4c14-b3d1-33035bef7c98	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
bcbdc105-58ed-4846-94f2-e0391e4ab452	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
19b90249-62b8-46d4-9a6e-18a44ff94a01	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	8f3594c8-3884-4d3e-a46e-c813edb9797f	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
a9416e11-0574-4186-a9da-5aab61175ac0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
256decb6-386c-43a6-990c-a48a8dcc6cc9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
5574cd94-9a7e-4c2b-8d2c-9af9ed0daab5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	9906114e-2eee-4dc3-a9de-1aff750dfa9c	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
4b0506df-5295-41ee-96ff-2c2c9c3874c7	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
abe842be-ed34-4ca2-a8b0-087600913285	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
a8eee2b1-78f4-4513-b763-dd9e700f3dd0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
2bd40795-6351-479e-a7b2-05c5125b96e1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
260f9d1a-8923-459a-8ddd-51083596bc2f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
e805f4b8-fb19-4f47-ab1d-2e70bfc3314a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
69734aaa-3c92-44ac-a614-f01648657078	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
bf29777a-948b-4754-94fe-b9a6bb957ef4	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
460e3f26-f01b-4435-90a6-709d260de68a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bf40fb9-9c63-4bf4-ad3d-04b54a76b388	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
9a878420-ee36-43ff-9061-b8ad2811301a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
78d77627-2f70-487d-a7de-7eaa037a85e9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
aa0115d5-3cca-4e14-a34e-ec835a6080fd	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
e2e02420-db62-4852-8096-45c5653a9cd9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	790d025b-75be-454b-b929-99a030355692	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
8ef1cd28-d656-4a3f-a3f4-a462b419aee5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
5a2964ed-7c2e-4c40-a325-9bc3008fae2a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
5df34f8a-4694-4bb0-b37d-b243522333c1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
e13b47b2-12f4-424c-ab17-696e55a0663e	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	6b360892-ab5f-4616-9f5a-f8631870e62f	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
ca299bdd-da94-4882-987f-29490418cfb7	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
2907932b-09b8-4275-b9b1-6dbd7464a8aa	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
e4155a48-34f8-46d6-9db1-beae2c18a44e	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
014ee1ab-6a6c-44d5-81fa-83d3510afa49	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
ef90f74b-a65b-4442-a2ad-7780eb6fc4a2	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
f701158a-57eb-4cfa-8153-def53ba8daf3	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
f640a7ad-050b-4e21-b4c3-0cd2534e95e8	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
057a73da-3c9e-42b7-b342-872323b98ead	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
49f3a4bf-b5d5-46e9-9706-d4ae3b1d48c8	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
15cff8f8-961d-4cfa-ac7e-195b48f0f9db	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
33d81d8a-9270-40f5-becd-4822eccff972	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
0d89f4a5-d42c-4dff-89aa-ceab62e58c26	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
661681f2-7433-435c-b121-906740414bde	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
318f1509-74af-4ff5-a784-689364540838	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
6bff0404-312a-4376-9b74-8b2a50038ace	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
10e8821d-af31-4019-bc40-9f9176ecc7ac	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
65d3fd90-1e82-4ad9-8938-7a877dd36de5	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
d21c51bc-e104-4810-b454-a62e13ace369	31fcb5e1-23f2-4589-b779-167352214b1f	2652386b-b7d7-41d8-ab9f-22e3a2e0357d	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
c12ca239-1557-404b-872e-ae2ffc6313bc	31fcb5e1-23f2-4589-b779-167352214b1f	c3c5cba3-9ea3-4561-8d45-86170d045b3c	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
db0310e0-d758-4afe-9ae5-c77cbdb0756c	31fcb5e1-23f2-4589-b779-167352214b1f	9f6f671b-8447-4c15-ad9e-a46c1460d3e0	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
23b26a2c-65b4-45fb-a36e-afee57f54db7	31fcb5e1-23f2-4589-b779-167352214b1f	52632d8a-533b-496a-95f3-c1ac746d10dd	fe91c0e4-2a48-48ab-8add-7b04733dcca6	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
f8888d2d-7ba4-4dc0-be56-dbfa8c633386	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	94450338-78b3-42c9-a9dc-321d2dafe56b	2e58fb3d-0641-434a-9250-55404ed268e8	2025-12-08 18:14:17.079003+00	2025-12-08 18:14:17.079003+00
742f1530-b20d-4bb2-9092-68c73b4a3ac7	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	d9d578b4-26b2-4a70-a38b-19e7648cc9c9	2e58fb3d-0641-434a-9250-55404ed268e8	2025-12-08 18:14:17.079003+00	2025-12-08 18:14:17.079003+00
8b58f275-2e87-4273-8123-7eecac82c4ef	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c8e940ae-9816-4b6d-8453-bac9c2722f4b	2e58fb3d-0641-434a-9250-55404ed268e8	2025-12-08 18:14:17.079003+00	2025-12-08 18:14:17.079003+00
306f99fd-71da-440b-a024-f8f15221fb63	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	e6f89ba1-b1c0-4510-9bc2-612366b4f3f1	2e58fb3d-0641-434a-9250-55404ed268e8	2025-12-08 18:14:17.079003+00	2025-12-08 18:14:17.079003+00
17b98ee5-01b2-4bab-908f-49de6d0c8134	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	709918a8-a0b3-4656-86d6-c7dc5aa1190b	249e7b77-4ca0-4d94-9e3a-1a97d07e72ff	2025-12-08 18:39:54.464437+00	2025-12-08 18:39:54.464437+00
5b383d34-9da8-44cd-a447-e5a7fa22ac2f	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c8416d7a-ee89-4260-b718-16c883906c82	249e7b77-4ca0-4d94-9e3a-1a97d07e72ff	2025-12-08 18:39:54.464437+00	2025-12-08 18:39:54.464437+00
d46b3446-7d27-44b8-ab08-078ac4a5bebe	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	3020a48b-073f-4d49-873a-426ced18f547	de893e4f-1bc9-4727-ae1f-3aea4c08b564	2025-12-08 18:41:13.384341+00	2025-12-08 18:41:13.384341+00
8a21d985-9f4c-4db4-967c-9aa1c771d689	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	709918a8-a0b3-4656-86d6-c7dc5aa1190b	de893e4f-1bc9-4727-ae1f-3aea4c08b564	2025-12-08 18:41:13.384341+00	2025-12-08 18:41:13.384341+00
d32d79b5-c0db-4620-816f-4ec1d07d6485	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c8416d7a-ee89-4260-b718-16c883906c82	de893e4f-1bc9-4727-ae1f-3aea4c08b564	2025-12-08 18:41:13.384341+00	2025-12-08 18:41:13.384341+00
c46211c5-3a2b-44c8-a660-ac22d24f31b0	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c8e940ae-9816-4b6d-8453-bac9c2722f4b	6b0008c3-22e4-4e74-a974-f7801a22129d	2025-12-08 18:41:28.164456+00	2025-12-08 18:41:28.164456+00
3d2b5b18-d27a-4b31-b22e-e863965ac85e	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	9eb9b3ef-7ce5-4a90-ab15-68b26a6d87b9	6b0008c3-22e4-4e74-a974-f7801a22129d	2025-12-08 18:41:28.164456+00	2025-12-08 18:41:28.164456+00
f8fdbd3a-0a5a-45dc-b66e-5190e79da939	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	b54233b5-9d8a-4f92-a4b1-3a244a3ae148	6b0008c3-22e4-4e74-a974-f7801a22129d	2025-12-08 18:41:28.164456+00	2025-12-08 18:41:28.164456+00
79b4c295-f466-41b8-8093-84aa12c66850	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	3020a48b-073f-4d49-873a-426ced18f547	86289a94-9156-475b-8d44-b1bf031858d4	2025-12-08 18:41:28.184281+00	2025-12-08 18:41:28.184281+00
5b3a48e5-a40a-42cb-b782-7325813160ab	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	709918a8-a0b3-4656-86d6-c7dc5aa1190b	86289a94-9156-475b-8d44-b1bf031858d4	2025-12-08 18:41:28.184281+00	2025-12-08 18:41:28.184281+00
47a9e6f3-0981-4b8b-bdc4-d38e33cdeef7	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	7d6643ac-c908-438a-99be-d45337888c77	86289a94-9156-475b-8d44-b1bf031858d4	2025-12-08 18:41:28.184281+00	2025-12-08 18:41:28.184281+00
e0a06672-6690-45c1-a37d-929e717c2896	3e8a705e-9742-43ea-96cb-89fe88aed058	76c88ea3-2fca-4c0b-a35a-119e17788de3	b3557670-8efd-4bdf-983c-57813c3bf7c3	2025-12-08 18:41:28.185539+00	2025-12-08 18:41:28.185539+00
e7a64145-7c8b-4126-8cfd-5bdf16164f3c	3e8a705e-9742-43ea-96cb-89fe88aed058	f0bccf2b-1bc2-4ddf-9d45-52946a21692c	b3557670-8efd-4bdf-983c-57813c3bf7c3	2025-12-08 18:41:28.185539+00	2025-12-08 18:41:28.185539+00
14c29844-b8ee-48a8-a404-d92b9ba3daaf	3e8a705e-9742-43ea-96cb-89fe88aed058	0861f48e-08cc-4766-94c9-06ca4a322544	b3557670-8efd-4bdf-983c-57813c3bf7c3	2025-12-08 18:41:28.185539+00	2025-12-08 18:41:28.185539+00
60aebf38-5a05-4c4c-b235-60d73fb73455	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c8e940ae-9816-4b6d-8453-bac9c2722f4b	cf6c7f1e-413d-4555-ab5e-9cd6d4e568ce	2025-12-08 18:41:55.528558+00	2025-12-08 18:41:55.528558+00
6940bd92-b25b-4a0d-ba30-61a53c0faa2b	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	faf61269-33ac-45d2-a3ce-53dcdd44f399	cf6c7f1e-413d-4555-ab5e-9cd6d4e568ce	2025-12-08 18:41:55.528558+00	2025-12-08 18:41:55.528558+00
673ca411-4f48-44df-9979-01035a220583	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	b54233b5-9d8a-4f92-a4b1-3a244a3ae148	cf6c7f1e-413d-4555-ab5e-9cd6d4e568ce	2025-12-08 18:41:55.528558+00	2025-12-08 18:41:55.528558+00
14c6de22-7f60-4d6a-9312-f69dea9b917b	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	3020a48b-073f-4d49-873a-426ced18f547	50eb73b2-0e38-4b2e-8231-037a18291d34	2025-12-08 18:41:55.834764+00	2025-12-08 18:41:55.834764+00
51e50295-3bd9-4f3a-a793-14f8072c8c43	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	709918a8-a0b3-4656-86d6-c7dc5aa1190b	50eb73b2-0e38-4b2e-8231-037a18291d34	2025-12-08 18:41:55.834764+00	2025-12-08 18:41:55.834764+00
8614ac81-c7a8-45c1-a442-882c93e1899e	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
cfa25e71-a9e8-44d4-90f0-426ce38fb73a	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
7fe082af-cab1-40a3-a5f1-2dd8cd6358e4	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
3764a918-5b52-4a2c-93d2-6c7d1e3ed639	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
5305dcdc-0b91-4331-9770-8ca7d0dc8d48	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
ea936b07-d2ea-4ae9-afd1-4810f72a85fb	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
e86cbcfa-ca0e-4a23-8fb2-1c72028aac16	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
fc5f78bc-b3f0-4b8f-9bcf-c31f5cd601c0	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
ec08da6e-4b49-4459-be61-6b6f88e7954c	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
ce35412d-da85-45ed-8bd4-c6850b79a304	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
ef034fb0-acb7-4b3b-8333-583ade9b4960	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
b44108a1-86f0-417b-8efe-3c9f68cd374b	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
77c9519b-034b-4c2b-a64d-a5497c1e272f	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
2612f0f9-773b-43c1-8dcd-89c225b434be	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
8dd0ec6d-9c11-4c25-952b-841c31d7be8f	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
2378e69b-b1d2-4e5c-ade5-7bbc371ad0d4	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
b4bc4069-38d6-49e4-bed0-5e43321ceb95	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
bdb55791-2dc3-4672-af62-d92625ad7766	31fcb5e1-23f2-4589-b779-167352214b1f	7188dbfb-d2f9-4d2e-8bc9-6b94b001a7dd	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
f63ee98f-6388-4bd7-add7-895dc8fef187	31fcb5e1-23f2-4589-b779-167352214b1f	d50935b3-32cc-4353-bce3-de0d3617b02f	dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
c061c89d-2872-47c9-b9af-3865fac4dbde	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
330e79ef-3ff4-4075-b7b4-7d64463ab30d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
94a48c4b-2d38-407f-81b6-467e7daacfbe	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
ed278c16-937e-4e9b-96cc-d41ddd2ea014	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
e358d00e-0705-4834-ac39-84323648fbbd	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
ae258a95-4361-48ee-a33b-7c61330d7051	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
39feb1a2-e652-4fe5-a817-e0d24af53b6e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
f4cbaa67-7da6-4167-889f-388c320b824b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
e0c150e9-28bb-40b7-b54e-5c27f4dd29b1	a28ceab1-d6a2-404e-b21b-fb9a14194e65	c797a155-accb-4272-82dd-844f650ed59a	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
8b9efcdd-caa6-415d-a49d-ed107f8049cf	a28ceab1-d6a2-404e-b21b-fb9a14194e65	e84ad97b-a61b-46f0-9cdd-523006f542eb	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
780a06a9-5e3d-4f65-aa2c-07d599b1691b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
ea9c1c5d-6436-4dbd-9be3-94dc80f0d098	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
82ccb9a4-552a-46da-8ad5-a4c0860660d5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
360812a4-2f5b-48a5-91be-05f685893f53	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
5101b56e-fc2b-4275-bafd-00ad4e13b7b6	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
fd41639d-6715-4fce-b5fa-30e485c6b066	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
cfa60e20-c2b8-4a1e-bc15-60967d9735b2	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
a60aa056-03ff-4acb-be11-c6ea2d67feb9	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
3c946402-b8de-49fc-ac83-fda20c4901cf	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	ff1a57c6-d8e8-4da6-b7ed-b31462732821	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
aeeba880-5e32-48b9-ae62-a2fa8328ce3f	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
165fefdb-d01d-48f1-bf55-42d1f5d4fcbc	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
94d49221-ce7b-4af9-8b4e-68aa342a8667	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
1da283be-79ad-4b87-bee9-021f7d082fef	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
82a70fd5-2eac-457f-8ca7-602ed561bb3e	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
99fafbda-1eb8-4f1a-a147-b9dac63d5e36	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
7809c768-cafe-484f-9231-ae8af2971b3a	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
7de59aa0-0ae1-403c-a7c8-676ef1a63822	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
df8b736b-738e-4641-b858-33e85515e3f2	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
0c26c365-21df-4809-ae1a-4509ed61fc93	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
3e82b1fa-14a4-4cd8-91d5-75940cde3f18	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
e6ee9296-42a8-4f47-88b7-04b8f3fe49b6	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
fb646fab-0a6d-4956-927b-3b8238465297	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
460f3540-6810-4b98-854f-634f2ae5df18	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
6e732948-b897-45f6-93ba-53306bdc9192	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
4612d9ee-a9f5-4f3e-a672-928f49f51e40	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
a92c36b5-996e-4692-8851-f49d1e2f1b48	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
68539345-dae2-4d20-99d9-a014cecd4a70	31fcb5e1-23f2-4589-b779-167352214b1f	d50935b3-32cc-4353-bce3-de0d3617b02f	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
c38d894b-862b-4a0d-b98f-1b6e828a894c	31fcb5e1-23f2-4589-b779-167352214b1f	afdbfef4-de59-4ee7-a46a-eddf4a9de311	4442fe37-6949-4e6b-b303-dded9ebc5b0b	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
75e3cc10-4129-4a4a-9df9-58ec0ad7bb0f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
e7b7eae1-5b34-4219-b5a4-4de1538571d5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
34bf4611-89b6-4e39-8e45-061bfbd9acf7	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
dc8b57af-74a8-4590-89f7-74cbd5e1ea02	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
23cd2fc3-d386-4505-93db-be60d791cf60	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
0830b2fe-3296-41af-927d-b3d5d2218fee	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
a8ed027b-66d3-4d73-ad3d-753b580b3853	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
6ac62af9-fbe4-4d90-b337-b2263bb4b270	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
16894937-28fe-4c33-9d62-137f487d7d04	a28ceab1-d6a2-404e-b21b-fb9a14194e65	c797a155-accb-4272-82dd-844f650ed59a	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
af6cad88-da9c-47c3-897a-20aed8b68346	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2518cbb6-7119-4af9-927b-6cfb5bf4c19e	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
6dc57008-8a36-485d-84af-744e0388e0fa	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
2e7b7de5-c659-49da-899a-3d62932186fe	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
d24662a8-9028-43db-a2b1-da890de279c8	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
5d19c220-f462-49a6-b8d4-f7432e7884f4	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
9f5c8d0b-f69a-4c24-986a-f53c7c898fa1	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
c9491104-a344-401d-b0c8-83636de950c1	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
1c037f8b-508b-4351-98cf-3e3ba0e58cd9	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
7945cdee-0a45-41ae-9a86-4f33df17e047	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
2201440e-5e16-4dfa-aa86-c9ed67f6f463	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
30df3589-a81c-4cc4-827d-9b7072e9fe40	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
30ac2af2-8ee7-4332-8608-700d2091deec	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	0c89ef3b-ae6a-45a3-8971-2a2738d3d69e	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
f966efab-325a-4130-9158-0cc1bd57fe42	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
08f6f3c1-d126-4ba2-8527-ed3fe1ee9af8	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
ef9bbfb1-bd91-42fd-b840-9f783bf4c36a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
beec651f-9376-487d-a57f-97b958db1e2d	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
a62bca07-28bf-4de9-bd9b-2320bcc7bcca	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
db98f56b-5194-4a73-b94f-e3720846bb77	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
a6d64833-5d58-44c9-bb0b-158da659d336	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
e265e400-be2f-470e-a41d-2afd6c6b57e6	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
da11a602-2d53-45c1-a282-5d1a9cda4400	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	45ab2fd7-a5a1-475e-b544-152d6720df33	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
09a25530-d554-4d5e-95bf-3f5a6f316870	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
920a631d-dda1-4d76-962f-a8fba47d4bda	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
b272b18f-bd5d-4d37-853e-56fd0f1c21ae	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
7abf9c49-2f7a-42c8-ad8e-7d0a565e5fe5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
d19970e3-acf4-4cc3-9176-dfa19639d108	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
79207a88-5b66-40d0-832b-f00aa675d1dd	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
8fe3eab2-570c-46bc-a866-b33dba8b2a34	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	f6e6454d-0700-4c79-aae1-c782411d0ce3	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
c70b9878-f4df-40f0-9ab5-6a22e6a09cd0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
463fa4d8-f578-4335-b8e6-843e035fdac5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
f39a641f-9fe2-45bb-95d1-8aff1f3e4d5c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	0c89ef3b-ae6a-45a3-8971-2a2738d3d69e	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
2d075c1e-74d5-4f48-a880-f5ad34bafdc8	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
ab4c597f-5e1d-4bea-a6f0-811e07057b12	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
2c4975bb-3e67-421a-98e0-b21a0e414355	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
33831cb0-ee14-4aee-b224-220e00a387c9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
2d160553-6d2c-4200-9892-ffd6cd0e5569	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
0ea384fb-34c9-4c77-8b9a-bdcea5be48bd	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
66a06de0-c485-40ac-98cd-1ac7429bd491	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
47b0f7f7-26b2-45f5-ba91-64a1ebb16a1a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
23cea391-229c-40a2-8e43-4ad19f34d3f1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	9d8ce2d8-0fae-4514-aefd-487f2fbb5923	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
11539a28-0210-432c-874f-2f93e4e67702	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
8f48637f-c502-4787-b558-c5e44f330365	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
0e19d1bd-1c89-4d8e-b457-c55aaef5ef08	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
9c898b6e-0a88-41c9-a79e-f23136965991	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
27dbc81c-e86b-413a-95cf-94eb1bc94925	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
b2be9198-fbf1-4c34-bdb1-763c59fe6ec5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
d8826cd3-d594-4079-91f0-0d823396ad4f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	cde60cd3-bf0a-4a83-9e07-89c1a932d82f	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
439c59a1-dc0a-440a-a4d4-c30123010b5b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
507875eb-3710-4413-ba26-995eac430b65	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
318b8a9a-cc5f-4416-8cab-dd7df00c9f76	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
ce22fb51-230e-4385-af48-e36393208837	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
5bfb4e29-1a24-4c30-ba52-233d0f6d6272	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
e5c85e7a-95b6-46b1-8e3b-52bfa024b41f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
99585f8b-d70a-4710-9ded-62bcd9d73290	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
b865d546-fbba-4e48-a218-09ab5257f42c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
fdc2245d-6fb1-41a3-aabc-a79d887aaef8	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
b3cabf4e-9f11-45f4-aa97-0ce88aa8bbbe	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
e59b27f3-accb-451a-a43f-26703790a425	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
7b03bb9c-71f9-4abc-befb-417e7686d08b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
d059b385-f59e-4456-befb-37a55332a5f0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
cab3c629-d383-41ac-b25a-6667ca936d3b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
5cf161a7-a64a-4dca-b821-db975e8e6a55	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
bca3834a-fadb-4e5f-882a-40b339b8a485	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
20f6284d-5a03-4db0-b15f-d03895fa3091	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
f3c24a63-5126-4d51-9a8f-e93e8353ca95	a28ceab1-d6a2-404e-b21b-fb9a14194e65	41b7a346-3ed8-4af2-9110-62d90f492343	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
7e6e502f-5106-423b-ab73-defde59d289b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	059a3f39-a329-4d81-a1bc-a5077ebc741a	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
09ae6b45-13b0-45bb-897c-1077c021f9de	a28ceab1-d6a2-404e-b21b-fb9a14194e65	245b6b90-dce1-4d39-958e-cda5790e3bb2	dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
93e63f58-e9e7-44c6-84c9-f89780610861	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
f02ecc94-1ea2-4a9c-a826-7ac2d2b6fe2e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
25d8e90f-07d4-427a-a101-56ab9e1bd636	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
b007751e-2754-4aa6-b53d-c87255c8abd6	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
04739bb4-717d-4b60-8f15-bfae63edb14e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
0841669e-ccad-4908-b75f-40254566acef	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
7707f9ab-fc55-4eda-8322-290378300e35	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
f06ac131-c958-4e27-a5f0-aeb035772353	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
57386dea-fed3-4a14-a615-0456402c051c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
18e3a291-b73e-48e6-97e6-d954891b1e05	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
46a62e9d-e467-484f-9a93-9640527eb94e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
2f1b5f56-b449-41a8-9566-6759036decf5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
72a0cf5f-1af5-467a-8be3-3b9388f8b04d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
abd6fc44-b580-4902-98e3-8076588181b5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
a08f4462-7bb4-4718-9002-4da339a085c8	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
3048aa43-5aef-4ba6-89f8-8be4feca4478	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
626cf9f8-7278-4cb2-9a65-94f758d8464a	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
1260e712-5854-4199-8725-d3c8fed829b0	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
1d21094e-ab2d-4176-82a3-c2363dfa0a64	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
49ecd2f8-df93-4f6d-9349-a088025eec6d	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
f5472c0d-0163-4338-99bb-a794f7a1a476	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
b583bd59-bcff-4b08-8074-9ba6707f7a55	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
dbc7e769-e5c4-476d-b744-806d4b8332fb	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
e3fd458e-9bc3-4b69-9cff-488b2130487d	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
6f5dc591-639d-4fbf-a461-cb4ca5144528	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
bdc0ab96-9972-48e0-9c91-3ffe015023da	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
6569620d-9519-4a14-bc73-8cd13ea4c913	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
41afbc90-4254-44db-b360-33a14d0f210e	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
22f52a1e-6cde-42d1-ab02-d7e9118a7266	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
7ef254f6-a4bc-470b-a64b-2fc8caa70647	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
6932eaa0-552f-452d-900e-9e6d47ff85cc	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
082ea4e3-bf48-419a-837c-421f75eed731	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
2b686ff2-0fcc-4775-be23-2a4a1f576ad1	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
91cce79a-40e8-40eb-aa24-ca79ae7c1b20	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
e72a520d-8755-4b87-9eec-87620bef05e9	31fcb5e1-23f2-4589-b779-167352214b1f	afdbfef4-de59-4ee7-a46a-eddf4a9de311	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
f8fc4521-a8df-4115-b01e-258ab1f798fe	31fcb5e1-23f2-4589-b779-167352214b1f	663ea842-bff5-4313-8e24-c81ee0c97163	e6ced538-0c2b-4982-b7d9-fb19b80b00c4	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
f13c76de-1949-4a05-9feb-b8e1c7154845	a28ceab1-d6a2-404e-b21b-fb9a14194e65	41b7a346-3ed8-4af2-9110-62d90f492343	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
244f1dc2-4662-4a3d-adb7-6ee0b4a7bf51	a28ceab1-d6a2-404e-b21b-fb9a14194e65	059a3f39-a329-4d81-a1bc-a5077ebc741a	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
baf58575-f4eb-4a84-9ae6-c45472e82823	a28ceab1-d6a2-404e-b21b-fb9a14194e65	245b6b90-dce1-4d39-958e-cda5790e3bb2	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
4613eb3d-e8e4-4773-8088-2d9388e29749	a28ceab1-d6a2-404e-b21b-fb9a14194e65	cee2f551-1841-4c84-ae30-6555196277ba	9881e1c3-3ebd-4e04-aea7-77db98a5c764	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
2280f44a-e5e8-4c5a-9e86-dac1f2d16a2a	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c8e940ae-9816-4b6d-8453-bac9c2722f4b	e70062f1-a42c-4e05-a06d-be69f02b4726	2025-12-08 18:39:54.48761+00	2025-12-08 18:39:54.48761+00
cccefbdb-20a4-4246-a4a9-c23f6be911a7	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	c14ce8af-ff97-4250-b218-c33f0badc492	e70062f1-a42c-4e05-a06d-be69f02b4726	2025-12-08 18:39:54.48761+00	2025-12-08 18:39:54.48761+00
52888274-5aa2-4817-bef8-d1b8f36182fa	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c6d872cc-254d-4eb3-be3d-28eb87105d9d	50eb73b2-0e38-4b2e-8231-037a18291d34	2025-12-08 18:41:55.834764+00	2025-12-08 18:41:55.834764+00
bbc11a0f-54fb-4143-a610-0d94a320b89a	3e8a705e-9742-43ea-96cb-89fe88aed058	76c88ea3-2fca-4c0b-a35a-119e17788de3	9c7f46c2-a93f-44db-94bc-b37940df2960	2025-12-08 18:42:07.11454+00	2025-12-08 18:42:07.11454+00
d5cea4cf-902b-4d47-97ab-af87a5d9e7ab	3e8a705e-9742-43ea-96cb-89fe88aed058	749acc37-2329-4330-9254-b73ee803f56e	9c7f46c2-a93f-44db-94bc-b37940df2960	2025-12-08 18:42:07.11454+00	2025-12-08 18:42:07.11454+00
294d4433-483e-4810-b409-ff93a5743766	3e8a705e-9742-43ea-96cb-89fe88aed058	17a4a454-7b0d-4d52-94a0-87250f35b5a1	9c7f46c2-a93f-44db-94bc-b37940df2960	2025-12-08 18:42:07.11454+00	2025-12-08 18:42:07.11454+00
279a79d6-e26e-4cf3-9a39-7fbfaf5b7179	3e8a705e-9742-43ea-96cb-89fe88aed058	0861f48e-08cc-4766-94c9-06ca4a322544	9c7f46c2-a93f-44db-94bc-b37940df2960	2025-12-08 18:42:07.11454+00	2025-12-08 18:42:07.11454+00
4c989163-a2f6-463a-b9a2-3ccb9847978a	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	3020a48b-073f-4d49-873a-426ced18f547	36ce7d77-9b3b-4839-a7a5-045f1eb56426	2025-12-08 19:08:16.966478+00	2025-12-08 19:08:16.966478+00
9e51550d-8dfd-44c0-ad9b-478673647ef7	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c9e1a973-830e-411f-ac29-277d19290304	36ce7d77-9b3b-4839-a7a5-045f1eb56426	2025-12-08 19:08:16.966478+00	2025-12-08 19:08:16.966478+00
38090f26-914c-4e94-9cca-6d970863bc7d	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	d627eb9a-a643-43aa-8473-3ce70c6d93ab	36ce7d77-9b3b-4839-a7a5-045f1eb56426	2025-12-08 19:08:16.966478+00	2025-12-08 19:08:16.966478+00
652ffa30-4a4e-4459-a562-449befe5459b	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c6d872cc-254d-4eb3-be3d-28eb87105d9d	36ce7d77-9b3b-4839-a7a5-045f1eb56426	2025-12-08 19:08:16.966478+00	2025-12-08 19:08:16.966478+00
cba6d60c-93bf-470a-81d1-6e92fcefec3a	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	80a3c7b8-d291-4daa-b6c7-b2b3a3c01da1	29ae677c-d49c-4c57-8ac4-3c84522cf6a5	2025-12-08 19:08:25.233666+00	2025-12-08 19:08:25.233666+00
63da79a6-b110-4380-953e-b4cd5301138e	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c9e1a973-830e-411f-ac29-277d19290304	29ae677c-d49c-4c57-8ac4-3c84522cf6a5	2025-12-08 19:08:25.233666+00	2025-12-08 19:08:25.233666+00
10749402-855d-4a96-ae55-768cfdc4e616	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	d627eb9a-a643-43aa-8473-3ce70c6d93ab	29ae677c-d49c-4c57-8ac4-3c84522cf6a5	2025-12-08 19:08:25.233666+00	2025-12-08 19:08:25.233666+00
daad20c6-0eff-492d-8407-fbf947e8e7d3	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c6d872cc-254d-4eb3-be3d-28eb87105d9d	29ae677c-d49c-4c57-8ac4-3c84522cf6a5	2025-12-08 19:08:25.233666+00	2025-12-08 19:08:25.233666+00
f21226c4-6a91-4761-a6a8-a29addc17c0f	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	80a3c7b8-d291-4daa-b6c7-b2b3a3c01da1	01bb5600-6b0b-4a02-aefb-4ca674fb0b01	2025-12-08 19:08:31.709611+00	2025-12-08 19:08:31.709611+00
f9c890f7-f764-4231-822b-b39a5b310b18	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	5494bb07-e68f-467f-8311-c746f371d730	01bb5600-6b0b-4a02-aefb-4ca674fb0b01	2025-12-08 19:08:31.709611+00	2025-12-08 19:08:31.709611+00
a391d04c-34bd-4fa2-a9a6-b822608c5274	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	d627eb9a-a643-43aa-8473-3ce70c6d93ab	01bb5600-6b0b-4a02-aefb-4ca674fb0b01	2025-12-08 19:08:31.709611+00	2025-12-08 19:08:31.709611+00
446148ff-0d3a-4eae-8cdc-b3601254af8c	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	c6d872cc-254d-4eb3-be3d-28eb87105d9d	01bb5600-6b0b-4a02-aefb-4ca674fb0b01	2025-12-08 19:08:31.709611+00	2025-12-08 19:08:31.709611+00
1dbe6142-ab50-4d62-adf4-834737bc3114	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	80a3c7b8-d291-4daa-b6c7-b2b3a3c01da1	bd0f06e8-fafd-4425-bc9e-0529cae863a0	2025-12-08 19:08:41.609181+00	2025-12-08 19:08:41.609181+00
fb0beb18-ae39-4f7f-b1a2-caf80c8f78d0	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	5494bb07-e68f-467f-8311-c746f371d730	bd0f06e8-fafd-4425-bc9e-0529cae863a0	2025-12-08 19:08:41.609181+00	2025-12-08 19:08:41.609181+00
f5e03394-6589-47c6-872b-92db8818f40f	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	d627eb9a-a643-43aa-8473-3ce70c6d93ab	bd0f06e8-fafd-4425-bc9e-0529cae863a0	2025-12-08 19:08:41.609181+00	2025-12-08 19:08:41.609181+00
4bc763fb-8b0f-41ad-810c-b0f43d39526b	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	1b21a3f8-d3f8-4b3a-868a-3a40b24c4fbd	bd0f06e8-fafd-4425-bc9e-0529cae863a0	2025-12-08 19:08:41.609181+00	2025-12-08 19:08:41.609181+00
01094bb2-0720-409d-8aec-8ba19ca8fda9	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	fbf45c00-0679-4801-9481-1aa332fce815	2025-12-10 16:48:41.89302+00	2025-12-10 16:48:41.89302+00
64459c7d-ef79-4228-86a3-f8b316623330	82732d9d-904b-4f60-bc34-dbd6dfd85b97	12ba2089-ae4e-49ae-bc04-e3d09c888c70	fbf45c00-0679-4801-9481-1aa332fce815	2025-12-10 16:48:41.89302+00	2025-12-10 16:48:41.89302+00
605fcb15-841c-4e47-836c-f12dd0306df9	82732d9d-904b-4f60-bc34-dbd6dfd85b97	d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	fbf45c00-0679-4801-9481-1aa332fce815	2025-12-10 16:48:41.89302+00	2025-12-10 16:48:41.89302+00
24aebcff-1b9d-4ac8-aea4-01c9e5a962bf	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	1951752b-063a-4f70-ae27-7af64d5e758d	2025-12-10 16:48:51.25144+00	2025-12-10 16:48:51.25144+00
3cbdf512-9b1c-46d6-832b-f697de03c7ee	82732d9d-904b-4f60-bc34-dbd6dfd85b97	5f07e592-8558-4ffc-aa74-488b3aaac5dd	1951752b-063a-4f70-ae27-7af64d5e758d	2025-12-10 16:48:51.25144+00	2025-12-10 16:48:51.25144+00
3cfd5425-3432-4d69-936b-cb1d9bea12d5	82732d9d-904b-4f60-bc34-dbd6dfd85b97	12ba2089-ae4e-49ae-bc04-e3d09c888c70	1951752b-063a-4f70-ae27-7af64d5e758d	2025-12-10 16:48:51.25144+00	2025-12-10 16:48:51.25144+00
c50bf1f0-d5e6-4cb0-b47b-e6391b8dc020	82732d9d-904b-4f60-bc34-dbd6dfd85b97	d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	1951752b-063a-4f70-ae27-7af64d5e758d	2025-12-10 16:48:51.25144+00	2025-12-10 16:48:51.25144+00
e9b460f1-db96-400e-b0d2-15c6f0238541	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	6402a1ce-5cc8-42e0-a3f2-20b33440d76d	2025-12-10 16:49:03.479122+00	2025-12-10 16:49:03.479122+00
b94c156c-0309-472b-b025-9be1e039d0b4	82732d9d-904b-4f60-bc34-dbd6dfd85b97	28de0554-fd24-4bd4-b056-2000640e9b1c	6402a1ce-5cc8-42e0-a3f2-20b33440d76d	2025-12-10 16:49:03.479122+00	2025-12-10 16:49:03.479122+00
8472d440-6b73-4f38-bedc-b2082efeed45	82732d9d-904b-4f60-bc34-dbd6dfd85b97	5f07e592-8558-4ffc-aa74-488b3aaac5dd	6402a1ce-5cc8-42e0-a3f2-20b33440d76d	2025-12-10 16:49:03.479122+00	2025-12-10 16:49:03.479122+00
e105614f-dc5c-4fa8-b1ff-3a11fbc9cba0	82732d9d-904b-4f60-bc34-dbd6dfd85b97	12ba2089-ae4e-49ae-bc04-e3d09c888c70	6402a1ce-5cc8-42e0-a3f2-20b33440d76d	2025-12-10 16:49:03.479122+00	2025-12-10 16:49:03.479122+00
9b052d7a-82e6-4dfc-977c-b54b97250cec	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	0d1125b1-012b-4d6f-8484-46996dd555b9	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
c2f42fe7-d801-42da-97e0-12c9698275d0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
c284df48-3d1c-4075-a307-211a13a8384f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
2b7edcff-3a67-45ca-a54e-90ec98b58d91	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
7df6efde-bb3e-47cb-bcdd-dad66e8751dd	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
9ad407ee-fb52-4442-a832-f3d968ded158	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
99fc9abc-d3f0-4bd6-bb0a-2116219bdb1c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
79874e38-bcdd-457f-b6a5-2dbaa00baaf9	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
a62c18c8-e8e8-4fcc-8885-706916a0e23c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
71c0deea-523f-4ea1-876e-acecb40b645a	a28ceab1-d6a2-404e-b21b-fb9a14194e65	41b7a346-3ed8-4af2-9110-62d90f492343	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
b0fc5ed5-5ee3-4d2f-bfda-1c44707cacb5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2518cbb6-7119-4af9-927b-6cfb5bf4c19e	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
b0dce324-4e40-4b07-9b2f-04b591199582	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
e06bbb90-9f99-4d77-b609-fd2c2ad23b65	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
b68c8011-54e3-4814-9cdb-e27f50d35406	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
98449f1e-4b0b-4f9a-8b7a-0cd1a138a691	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
efea8565-49e7-40ab-b79e-90ee32c96e08	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
ae1d5ab7-1d73-4a60-ae20-c1d2476ff55c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
6c8d1552-7286-49e0-9840-718c66e4d66d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
a16cdeea-17ea-4584-9659-c9f7c8e2443b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
217aa652-4cdc-4bcf-a48c-fd605fc7bacb	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	b814cc7e-c3d1-4329-ab1a-67bf12589894	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
d4736bea-22f5-4184-839b-85a174ef6073	a28ceab1-d6a2-404e-b21b-fb9a14194e65	74451709-c9e1-40e1-90c3-66b397c70f02	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
08fe0813-784c-4aa3-80e0-7c5419e98105	a28ceab1-d6a2-404e-b21b-fb9a14194e65	6f957543-9f09-4c50-b88a-074c40c5fd70	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
8549c16d-328f-4698-a553-3a6bb9dcc894	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f3ce2edd-a497-4baf-8f02-b1e22963ddd7	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
6d0bfa58-a5ea-42d0-a603-7f90110157b6	a28ceab1-d6a2-404e-b21b-fb9a14194e65	0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
8d324b2c-0767-445b-ae1d-012799de08ff	a28ceab1-d6a2-404e-b21b-fb9a14194e65	272af30b-6cd3-4dd5-aa91-21f2c5056895	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
993194db-6be5-47df-b423-6d93138f812e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
97135b26-f15a-47cc-a0c6-3ab552c9d947	a28ceab1-d6a2-404e-b21b-fb9a14194e65	067186d1-02a2-4994-ad1f-d39dcb736873	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
7e10b546-32d0-44c1-836e-3f76b87956fa	a28ceab1-d6a2-404e-b21b-fb9a14194e65	739565c2-16b9-40af-9b9e-05c01b36a621	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
7e039357-4587-488b-a68e-82e184c8de5d	a28ceab1-d6a2-404e-b21b-fb9a14194e65	41b7a346-3ed8-4af2-9110-62d90f492343	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
b5f6c234-844a-474f-bdf2-79e597b65bf4	a28ceab1-d6a2-404e-b21b-fb9a14194e65	059a3f39-a329-4d81-a1bc-a5077ebc741a	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
7f626839-a9b6-4a7d-981b-84a68b263b9b	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b6ebbc72-3cd2-4f91-a810-d858b36932f5	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
5c5bd4b5-adee-4d41-8bca-eb7eb98d628e	a28ceab1-d6a2-404e-b21b-fb9a14194e65	56ac6278-a819-48d4-b8f3-291a7a354b94	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
94b71139-95ee-4b62-ac37-2d852c07ec54	a28ceab1-d6a2-404e-b21b-fb9a14194e65	70b34c18-7d83-4b4d-8c83-b591a4429cdf	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
20560ce4-0a41-43c1-ae12-c0462ec751d9	a28ceab1-d6a2-404e-b21b-fb9a14194e65	13435208-966b-432b-a423-f474571c492c	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
10faccba-ebb0-41c7-8281-3e6a54b23a50	a28ceab1-d6a2-404e-b21b-fb9a14194e65	fca2e66f-4d28-4876-b196-c9f0f88fffef	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
ab13d227-a367-4ad8-bbb5-f15ece0659a1	a28ceab1-d6a2-404e-b21b-fb9a14194e65	02776bc3-699e-4aaf-b8c2-f6b897e09b99	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
e7109a1f-2ba6-458c-857f-ef25874ff7b0	a28ceab1-d6a2-404e-b21b-fb9a14194e65	ce955ff2-06fb-4e28-aa72-77a311d73dce	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
5ed04971-6477-4af0-a9ef-92a826665a15	a28ceab1-d6a2-404e-b21b-fb9a14194e65	5ee2ee3e-f358-4f59-9bd2-c45809458fe0	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
677572a6-72ec-45cf-be8a-ac728756cf64	a28ceab1-d6a2-404e-b21b-fb9a14194e65	30eb0f31-9dfd-470e-9f59-41d624444579	1b460ba5-b6ed-44ef-b275-eb41c85ade8f	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
c04b8354-7ea1-45aa-8980-8d7dc54d0f2d	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
f10ed0c9-7700-4e0c-80ca-83fc9c75589e	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
a922ab81-f0b3-4dae-88ff-603fb9b23e46	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
f213ccba-4cbc-4c30-bf7a-787e56f39fda	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
930f60d6-d4c9-4f18-bb61-7fc4e9cb10bc	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
c8abeb73-6f7d-47ee-a9b2-9125d7d1cf8c	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
951bfe81-21bc-41ad-b540-78362d331f31	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
aea7c97a-8f0a-4e78-b8a4-ffc57f78e17a	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
edcb5409-6459-44ff-ba2e-0f10a70a9a9c	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
ee8985e1-1fbc-4a67-8980-6b9b218b600e	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
8ab29cd5-8932-438b-b94c-cd88d3aacfc2	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
bbb33464-05c0-419f-91fc-993470189fc1	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
8ee3ff16-0f8a-4769-afb2-5643e2602619	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
89394806-0043-4a59-9381-56f2ab2a8335	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
7a6fa6b5-85f0-42ad-9e0c-164982d6a3d6	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
03b1463d-4214-4adc-b2cf-c5635883c410	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
afdf7b9b-2a2b-4864-9347-a3aff8983d92	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
74ff41ce-e284-45e5-81d7-a6be803f304d	31fcb5e1-23f2-4589-b779-167352214b1f	663ea842-bff5-4313-8e24-c81ee0c97163	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
d1523ba2-529e-4d33-80e2-e02043e5321e	31fcb5e1-23f2-4589-b779-167352214b1f	2652386b-b7d7-41d8-ab9f-22e3a2e0357d	c4f531da-19c4-48cc-b22b-86617413672a	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
d4772bc9-0480-4465-8050-5f7323ef34a9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
15e13100-05da-4f90-893f-8db868ad5085	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
c275d5fc-3d89-4e58-8fb9-20ee98ba0efe	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	9906114e-2eee-4dc3-a9de-1aff750dfa9c	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
5ec642d7-c3eb-4b1a-a7f4-b228da4eb03c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
032c4b8b-a774-4488-83ce-37316f0d16d1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
bae7317d-b130-4117-843c-df991ebd237f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
a902613f-a2d0-4aa7-8f90-0ce0dfe24208	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
738f962c-e1be-40de-9b02-74c669231407	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
cbd0f7ad-aac7-4487-bfbb-bd24d9664d3b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
5b124ee3-d7f2-45bf-88d4-c333ca9ed2be	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
5220d5fd-5801-46dc-8d0a-24c95ad128e8	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
a6816ce8-43c6-4cb7-8f7a-bfc14721ec02	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	9d8ce2d8-0fae-4514-aefd-487f2fbb5923	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
f0a414d5-37fd-452f-9737-d2a2cda494b0	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
261a1b4c-c6ea-4987-9162-c5158a0a12e1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
455024e4-d59b-4c61-b90f-ef56db9386d6	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
b11731fb-f583-4115-84ee-74b19db8ecb6	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
428eae52-1aa8-443e-9a4c-55aff00234b1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
323d0abc-4467-4de6-bc1b-48f4cb9490a9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
2ac51071-b595-4b6f-ace6-d475dceefa00	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	ecd69e76-4439-4179-bd5f-ac447fe85ebe	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
857c5cea-18f8-4acb-8c73-dff6b6afb4a7	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
3fed89c4-fcd3-462c-b05b-9ec1f77ef894	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
6c1cab71-5765-4879-a2c5-218095a21483	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
dda291d5-71ea-4584-8855-0c847b39b98a	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
25c55678-4cc4-47d7-bc65-8d699364e60b	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
d0ceb909-d64e-4671-82fa-054afb2d2d1d	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
d0f42bff-be99-4196-bf87-0e0ff779bf88	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
4c54aec5-2b3d-4355-b70f-fcd9b21a6da0	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
b311db08-df51-4fdf-af21-c41e87f49ccf	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
6c596cf7-3d0a-4c40-8821-018af99755a9	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
d083737b-8b44-4141-816a-6d428fd5dfd0	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
5c63b88d-83a2-42f1-92b9-fd1caf6f85c9	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
431864ef-43eb-404f-b123-2de4305b1259	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
b059a46a-bbc1-4689-bcfa-92b45814ac69	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
83cdb845-67de-491a-af93-964755b1ffad	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
a7d35dfc-afed-48b8-a1ba-9ab9ae2b817e	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
f994f29e-7103-40a5-beed-df2b3e2a740c	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
a49f5824-bfde-433e-a75b-7b292f053890	31fcb5e1-23f2-4589-b779-167352214b1f	2652386b-b7d7-41d8-ab9f-22e3a2e0357d	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
c842aaaa-53a0-4a7b-b79c-db1c15c02e93	31fcb5e1-23f2-4589-b779-167352214b1f	c3c5cba3-9ea3-4561-8d45-86170d045b3c	bbc98866-27c3-418c-b354-f669c4a59f33	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
d3c9fd38-7971-4da4-bee5-adbdfd2c97c1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	84b319ed-3b4e-4068-8abf-ac9e496d1542	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
10d37553-ebdd-4f82-b281-9f2f807a6d9e	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	776904ab-31a5-4f43-9a0e-b32607df0bb4	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
2d7a352b-dee2-46e0-b772-dc5511221c35	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	9906114e-2eee-4dc3-a9de-1aff750dfa9c	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
d2b0b6d8-cb2e-469e-a9f8-cc1251dcdc6e	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
455efcc8-8e4c-4f6f-bf09-e9b48d2dadbb	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53700e20-177e-4aee-b189-25886bdd1078	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
be52e33d-52a3-4958-9d1d-754d4ab7412d	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	c3ca5101-f966-4119-bbbe-7f368e7466df	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
a99af07b-95ee-4966-b508-045031d1238f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d85c9434-3824-4de7-ab00-88e9708b80da	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
bc6f5e49-1a9c-4ec4-a906-2a149021fd49	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	7ea93931-2f6c-4c5f-9db7-2f5748f2e091	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
946e12fc-21e7-4029-96c5-b553a5f80a96	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f3e78c0a-e119-4dc2-8169-045b27a5a7b3	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
0b47b6cc-b018-4664-ae31-be669f4baf5f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5e41edba-d18e-473a-80f6-ce485511ad1a	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
b83c705f-c90f-4b97-b47f-02461ece49b2	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	53cacfa6-b868-427f-b0eb-5f34b12167a3	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
3af83718-4a60-4a4f-a31d-b7f71f8b4472	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bf40fb9-9c63-4bf4-ad3d-04b54a76b388	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
d91be560-6779-4907-9527-d73e6b345b7a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	70a33671-d314-40c9-8b84-bd8b869720ba	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
6abc1c89-d4ff-48ee-98b2-ecf760930491	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
a9b9884b-fd92-4dc8-a521-be0c5e378a80	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	759181c3-67db-4b94-8d65-7634e955f04e	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
a49f9351-a081-4b50-8bd4-b8cabd4e639c	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	b2647bf0-54f7-4348-9f31-c52b5377ff50	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
a6b889ab-c714-409d-9e17-5abf6082f412	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	2098a6c3-456e-45c1-9e1b-40b58e442d8c	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
d7afbf45-b4f6-417e-ad7e-60d4f23cf521	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	359c312c-2289-4e1e-beae-0665ae696946	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
4629f251-b13c-4ce1-b590-ed704330b4d5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	87accdda-6a67-4123-b6c2-fc2697ce6876	4cbe15d1-3b20-4374-a2ef-09daf084a68f	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
bbb79542-417c-4ba6-a40a-8397abe4c601	31fcb5e1-23f2-4589-b779-167352214b1f	15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
8de56a72-7c5a-4d6f-b981-bb140cb93ae1	31fcb5e1-23f2-4589-b779-167352214b1f	ef3b5456-2d2e-4e96-bd05-721a247f9fee	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
ee3b0c58-99ca-4bc4-a661-840d9e318cbb	31fcb5e1-23f2-4589-b779-167352214b1f	d630f143-3211-4785-8c35-bf0b2b4d25da	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
832918c4-c7a4-4baa-af2a-1394f9b08f27	31fcb5e1-23f2-4589-b779-167352214b1f	590afcbf-a281-4db3-95a0-24890160f859	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
060b8b34-1d86-49a0-a97b-2eb608492bd9	31fcb5e1-23f2-4589-b779-167352214b1f	053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
b8d30f36-1396-492e-a6e9-f58a949fc310	31fcb5e1-23f2-4589-b779-167352214b1f	f800834e-20d0-4d91-991d-51990b37c807	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
2172d21e-5d98-4cc3-8914-838dc7ebaa29	31fcb5e1-23f2-4589-b779-167352214b1f	0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
3d003c9e-10bf-4441-8bb8-ef3dc2ac3f0c	31fcb5e1-23f2-4589-b779-167352214b1f	b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
8f99d88d-a495-498c-bdd1-e792092921e7	31fcb5e1-23f2-4589-b779-167352214b1f	bf16613a-e1a1-4770-879d-ce39a3475340	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
5b58e6e3-1260-4339-9aca-16c7c810225a	31fcb5e1-23f2-4589-b779-167352214b1f	fa1dcbc9-705a-4fa7-be84-3e9955e79090	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
3bdfd38e-a4d8-4fad-8343-cd309655af9a	31fcb5e1-23f2-4589-b779-167352214b1f	5bd67143-d039-4d00-8f68-8dd6e5474352	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
bf9f4a58-fbf2-4e7a-842b-d32cf2f28bcd	31fcb5e1-23f2-4589-b779-167352214b1f	7564b13d-7b7e-44ce-b7ff-b80829c89d2b	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
f8e85232-d980-4a66-9d2d-d858e23f89aa	31fcb5e1-23f2-4589-b779-167352214b1f	17100167-0f3f-41e8-b028-bddac3132dbd	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
2a51dbc0-2ab5-4cad-8c2c-59d9f5aeb7d7	31fcb5e1-23f2-4589-b779-167352214b1f	cfac54dc-9d2e-4dd9-80af-1d83402afa58	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
289fe3cc-6e85-40f5-8e9d-4ac041da31d2	31fcb5e1-23f2-4589-b779-167352214b1f	0a8aaa9a-2e0a-47db-a1e2-50533850b514	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
09a7c994-9f4b-435a-b834-1a222a693f23	31fcb5e1-23f2-4589-b779-167352214b1f	fea73af7-dc70-4ada-a8ad-b58f0a4a9903	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
3f87b5b9-c694-43a4-b771-685f374403e9	31fcb5e1-23f2-4589-b779-167352214b1f	7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
470de730-e2eb-4959-bcba-21ef70dc353c	31fcb5e1-23f2-4589-b779-167352214b1f	2652386b-b7d7-41d8-ab9f-22e3a2e0357d	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
62fb09ea-2adb-46cd-8fe5-33f67e7f2eb9	31fcb5e1-23f2-4589-b779-167352214b1f	c3c5cba3-9ea3-4561-8d45-86170d045b3c	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
c95a3aef-126d-4e8e-9470-2e3a56378a4e	31fcb5e1-23f2-4589-b779-167352214b1f	9f6f671b-8447-4c15-ad9e-a46c1460d3e0	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
85e0786f-3417-4b2b-8537-aad7712ba27e	31fcb5e1-23f2-4589-b779-167352214b1f	0cd08ff6-5795-4f84-8484-342a4ba424b2	20baf6d9-d7e7-4f31-82d0-cd60e0348cda	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
6b86c6a8-12a4-47a4-be22-84f16d61615d	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	614677d4-8d12-4992-8ad6-7e0d89bc1a93	2025-12-10 16:49:13.07186+00	2025-12-10 16:49:13.07186+00
3f815873-d0e7-4a6b-ae6d-8f5f8a804116	82732d9d-904b-4f60-bc34-dbd6dfd85b97	28de0554-fd24-4bd4-b056-2000640e9b1c	614677d4-8d12-4992-8ad6-7e0d89bc1a93	2025-12-10 16:49:13.07186+00	2025-12-10 16:49:13.07186+00
01932ce0-2633-4007-9a85-08498e351ef6	82732d9d-904b-4f60-bc34-dbd6dfd85b97	76440291-a906-49bf-916e-e5330f8e8d67	614677d4-8d12-4992-8ad6-7e0d89bc1a93	2025-12-10 16:49:13.07186+00	2025-12-10 16:49:13.07186+00
cfabeff3-2714-4a82-aadb-9326d57920f5	82732d9d-904b-4f60-bc34-dbd6dfd85b97	12ba2089-ae4e-49ae-bc04-e3d09c888c70	614677d4-8d12-4992-8ad6-7e0d89bc1a93	2025-12-10 16:49:13.07186+00	2025-12-10 16:49:13.07186+00
5aa363b5-174b-4209-bc5f-ced6be6c863b	82732d9d-904b-4f60-bc34-dbd6dfd85b97	d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	614677d4-8d12-4992-8ad6-7e0d89bc1a93	2025-12-10 16:49:13.07186+00	2025-12-10 16:49:13.07186+00
de24f7a2-c189-4e38-8664-6abfcda130e5	80af13d8-3dcd-41e6-9e1f-6932888266da	18063347-1b0e-4b21-b458-15c32b0bf751	23cd7e73-8fdb-4865-9e25-3c6435929e76	2025-12-10 16:49:13.521552+00	2025-12-10 16:49:13.521552+00
3a87c686-aa2e-45be-bef5-8d63842b1ddb	80af13d8-3dcd-41e6-9e1f-6932888266da	1b1156ea-f6d5-43cd-9ce2-ab00d275276d	23cd7e73-8fdb-4865-9e25-3c6435929e76	2025-12-10 16:49:13.521552+00	2025-12-10 16:49:13.521552+00
4b0c6776-5b67-4a17-8498-fe68b17f0fdc	80af13d8-3dcd-41e6-9e1f-6932888266da	0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	23cd7e73-8fdb-4865-9e25-3c6435929e76	2025-12-10 16:49:13.521552+00	2025-12-10 16:49:13.521552+00
0916ebc1-f1c7-47a7-85f0-d99bae62e0ac	80af13d8-3dcd-41e6-9e1f-6932888266da	fa97540a-9bbb-4da5-9f23-754cc9319db4	23cd7e73-8fdb-4865-9e25-3c6435929e76	2025-12-10 16:49:13.521552+00	2025-12-10 16:49:13.521552+00
088120fd-9e1a-41cc-9528-aa9f4f6867cf	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	23cd7e73-8fdb-4865-9e25-3c6435929e76	2025-12-10 16:49:13.521552+00	2025-12-10 16:49:13.521552+00
b4c4f8d8-2f42-4bf0-bacb-7bc8ecab8352	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	884ace89-391c-40ee-bebe-1badab2e7e42	2025-12-10 16:49:13.99375+00	2025-12-10 16:49:13.99375+00
8fe359d0-5fc2-4e76-a934-757ca3d8329f	1bbe551a-fa18-4df7-8897-2d15055d5c28	7fbe9247-d309-4dd9-977e-ac7c4a0bb1da	884ace89-391c-40ee-bebe-1badab2e7e42	2025-12-10 16:49:13.99375+00	2025-12-10 16:49:13.99375+00
db55c32e-fb2c-45be-845c-c1683b2a87b3	1bbe551a-fa18-4df7-8897-2d15055d5c28	ae7ccb0e-4f73-4236-a69a-075ae99b1de7	884ace89-391c-40ee-bebe-1badab2e7e42	2025-12-10 16:49:13.99375+00	2025-12-10 16:49:13.99375+00
5c074e7a-aa87-4fed-91a8-e2491e14cf0a	1bbe551a-fa18-4df7-8897-2d15055d5c28	181da39c-f05b-492e-a911-62350fb24c5c	884ace89-391c-40ee-bebe-1badab2e7e42	2025-12-10 16:49:13.99375+00	2025-12-10 16:49:13.99375+00
e5c1e3d1-4fcd-4684-b1f5-a35713e38028	1bbe551a-fa18-4df7-8897-2d15055d5c28	266a6184-9cd4-489f-a486-d0463304c90b	884ace89-391c-40ee-bebe-1badab2e7e42	2025-12-10 16:49:13.99375+00	2025-12-10 16:49:13.99375+00
0d765294-50e1-465d-b87e-9a4b49b6ceb6	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	731c1cdd-3a88-4ed0-b23e-8d053cc9ec53	2025-12-10 16:49:28.668133+00	2025-12-10 16:49:28.668133+00
e749362c-a124-4feb-bb68-6fc25565f1b8	1bbe551a-fa18-4df7-8897-2d15055d5c28	7fbe9247-d309-4dd9-977e-ac7c4a0bb1da	731c1cdd-3a88-4ed0-b23e-8d053cc9ec53	2025-12-10 16:49:28.668133+00	2025-12-10 16:49:28.668133+00
35096be3-3951-420e-957f-2bd21a281b58	1bbe551a-fa18-4df7-8897-2d15055d5c28	5f8dc89d-0bc0-4438-8c97-af406ff9a8df	731c1cdd-3a88-4ed0-b23e-8d053cc9ec53	2025-12-10 16:49:28.668133+00	2025-12-10 16:49:28.668133+00
5cd5b6cd-d232-4e45-b38a-07589e0f68f5	1bbe551a-fa18-4df7-8897-2d15055d5c28	181da39c-f05b-492e-a911-62350fb24c5c	731c1cdd-3a88-4ed0-b23e-8d053cc9ec53	2025-12-10 16:49:28.668133+00	2025-12-10 16:49:28.668133+00
08829b61-ad00-4f12-b2ef-52ede9191ad9	1bbe551a-fa18-4df7-8897-2d15055d5c28	266a6184-9cd4-489f-a486-d0463304c90b	731c1cdd-3a88-4ed0-b23e-8d053cc9ec53	2025-12-10 16:49:28.668133+00	2025-12-10 16:49:28.668133+00
d075b5cc-18f2-45d9-ae56-b54f401c4a5a	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	287c3542-bada-4229-84d9-e8d0cadd1e67	2025-12-10 16:49:45.216132+00	2025-12-10 16:49:45.216132+00
0c122dd7-e2cc-41bd-b596-71096544594f	82732d9d-904b-4f60-bc34-dbd6dfd85b97	28de0554-fd24-4bd4-b056-2000640e9b1c	287c3542-bada-4229-84d9-e8d0cadd1e67	2025-12-10 16:49:45.216132+00	2025-12-10 16:49:45.216132+00
55d41346-04e8-451c-a067-d54e00c09f4d	82732d9d-904b-4f60-bc34-dbd6dfd85b97	76440291-a906-49bf-916e-e5330f8e8d67	287c3542-bada-4229-84d9-e8d0cadd1e67	2025-12-10 16:49:45.216132+00	2025-12-10 16:49:45.216132+00
f928451a-a95d-4506-b181-79f7c1994573	82732d9d-904b-4f60-bc34-dbd6dfd85b97	8781578c-e06a-4009-8fff-fc7584745524	287c3542-bada-4229-84d9-e8d0cadd1e67	2025-12-10 16:49:45.216132+00	2025-12-10 16:49:45.216132+00
934ddd82-29b3-4312-80fc-d3bca9603bd9	82732d9d-904b-4f60-bc34-dbd6dfd85b97	d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	287c3542-bada-4229-84d9-e8d0cadd1e67	2025-12-10 16:49:45.216132+00	2025-12-10 16:49:45.216132+00
a60875c5-ee07-4d48-9b52-67856bafb611	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	376eec01-7036-45eb-ae37-8353aa9a318e	2025-12-10 16:49:46.697773+00	2025-12-10 16:49:46.697773+00
f4764407-1e5d-4d75-a0b2-53f045b095c1	1bbe551a-fa18-4df7-8897-2d15055d5c28	7fbe9247-d309-4dd9-977e-ac7c4a0bb1da	376eec01-7036-45eb-ae37-8353aa9a318e	2025-12-10 16:49:46.697773+00	2025-12-10 16:49:46.697773+00
8acc10d7-1845-47bd-aa8b-32eb6066db10	1bbe551a-fa18-4df7-8897-2d15055d5c28	5f8dc89d-0bc0-4438-8c97-af406ff9a8df	376eec01-7036-45eb-ae37-8353aa9a318e	2025-12-10 16:49:46.697773+00	2025-12-10 16:49:46.697773+00
ea18b91b-d4ac-492c-94d5-ccb36a6046b3	1bbe551a-fa18-4df7-8897-2d15055d5c28	5739a7d7-2efb-4572-83d6-0ba02ca5e5f3	376eec01-7036-45eb-ae37-8353aa9a318e	2025-12-10 16:49:46.697773+00	2025-12-10 16:49:46.697773+00
983f4a46-beaf-46fa-b2a7-c20ed7e8216c	1bbe551a-fa18-4df7-8897-2d15055d5c28	266a6184-9cd4-489f-a486-d0463304c90b	376eec01-7036-45eb-ae37-8353aa9a318e	2025-12-10 16:49:46.697773+00	2025-12-10 16:49:46.697773+00
2a21876a-446f-4fc5-a9fe-b6c906ae3181	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	05a00379-5cc7-4d9f-a7c5-ebf35c641322	2025-12-10 16:50:12.839074+00	2025-12-10 16:50:12.839074+00
04ab8dee-0f73-427e-86e3-ddb0b798c480	82732d9d-904b-4f60-bc34-dbd6dfd85b97	28de0554-fd24-4bd4-b056-2000640e9b1c	05a00379-5cc7-4d9f-a7c5-ebf35c641322	2025-12-10 16:50:12.839074+00	2025-12-10 16:50:12.839074+00
69095759-bd3d-43e4-926f-c9df83f7d3b6	82732d9d-904b-4f60-bc34-dbd6dfd85b97	76440291-a906-49bf-916e-e5330f8e8d67	05a00379-5cc7-4d9f-a7c5-ebf35c641322	2025-12-10 16:50:12.839074+00	2025-12-10 16:50:12.839074+00
f922c812-c951-44ff-9473-19252016ecac	82732d9d-904b-4f60-bc34-dbd6dfd85b97	062227e3-a61f-4acf-8799-0afc8423d095	05a00379-5cc7-4d9f-a7c5-ebf35c641322	2025-12-10 16:50:12.839074+00	2025-12-10 16:50:12.839074+00
0a3587ac-b216-4328-af81-516d39412a38	82732d9d-904b-4f60-bc34-dbd6dfd85b97	d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	05a00379-5cc7-4d9f-a7c5-ebf35c641322	2025-12-10 16:50:12.839074+00	2025-12-10 16:50:12.839074+00
17ce3f07-483d-4365-b436-581ec2540988	80af13d8-3dcd-41e6-9e1f-6932888266da	18063347-1b0e-4b21-b458-15c32b0bf751	ccc8318f-ba0e-410b-8a5a-d395969216fa	2025-12-10 16:50:13.321085+00	2025-12-10 16:50:13.321085+00
f4193ec0-c41a-42d0-96f9-fa81349f04d4	80af13d8-3dcd-41e6-9e1f-6932888266da	1b1156ea-f6d5-43cd-9ce2-ab00d275276d	ccc8318f-ba0e-410b-8a5a-d395969216fa	2025-12-10 16:50:13.321085+00	2025-12-10 16:50:13.321085+00
c700331f-0823-46d6-8f55-79ce9815370a	80af13d8-3dcd-41e6-9e1f-6932888266da	0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	ccc8318f-ba0e-410b-8a5a-d395969216fa	2025-12-10 16:50:13.321085+00	2025-12-10 16:50:13.321085+00
45961b55-451f-40ce-a570-900a868981af	80af13d8-3dcd-41e6-9e1f-6932888266da	846f2df7-caef-4a9a-adc8-218001827c98	ccc8318f-ba0e-410b-8a5a-d395969216fa	2025-12-10 16:50:13.321085+00	2025-12-10 16:50:13.321085+00
ddfb23c3-d096-4ae5-800a-6162804bbec2	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	ccc8318f-ba0e-410b-8a5a-d395969216fa	2025-12-10 16:50:13.321085+00	2025-12-10 16:50:13.321085+00
93703db7-d504-44e0-9e93-26eeb3085aa1	03ebf868-ea91-44d9-9dda-e328e13d3561	e5a8234a-2ad8-4a4b-9e55-fe99b4be6fb7	f3f3cbaf-d2ed-47a6-b4f8-425a354cd07f	2025-12-10 16:52:22.533923+00	2025-12-10 16:52:22.533923+00
c3247d26-71b2-4ef0-bafd-1101d40fa026	03ebf868-ea91-44d9-9dda-e328e13d3561	e60f217c-f365-419a-aa14-fbb1d6bde4c2	f3f3cbaf-d2ed-47a6-b4f8-425a354cd07f	2025-12-10 16:52:22.533923+00	2025-12-10 16:52:22.533923+00
a8756854-6d44-4ac8-925d-67706ae3b37d	03ebf868-ea91-44d9-9dda-e328e13d3561	00f7ff7e-9454-4454-b3a3-8252088b1c01	f3f3cbaf-d2ed-47a6-b4f8-425a354cd07f	2025-12-10 16:52:22.533923+00	2025-12-10 16:52:22.533923+00
bcb2bef6-89d8-4ac8-9ec5-33c3fe309357	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	f3f3cbaf-d2ed-47a6-b4f8-425a354cd07f	2025-12-10 16:52:22.533923+00	2025-12-10 16:52:22.533923+00
7ee3703b-6ab3-4345-b604-1c280e6d4961	6926a156-9533-45dc-bcb6-b716ab914f46	4d106f8b-5fa9-497e-bc2e-7439e78c12a1	798b2ba7-c56d-4692-8863-6c7ed546314b	2025-12-10 16:52:37.710904+00	2025-12-10 16:52:37.710904+00
eb639c70-396a-4403-8d1e-19fc877b32c2	6926a156-9533-45dc-bcb6-b716ab914f46	baaad99a-3c3d-4a47-a089-329d457461b8	798b2ba7-c56d-4692-8863-6c7ed546314b	2025-12-10 16:52:37.710904+00	2025-12-10 16:52:37.710904+00
ed04ab06-3d75-4753-97bf-9eebce8656dc	6926a156-9533-45dc-bcb6-b716ab914f46	2537afee-2beb-4c19-89af-7ac073c1d91a	798b2ba7-c56d-4692-8863-6c7ed546314b	2025-12-10 16:52:37.710904+00	2025-12-10 16:52:37.710904+00
6833df7d-a6d4-45ee-89ca-a6ce1cdebcf4	6926a156-9533-45dc-bcb6-b716ab914f46	baa5eb1f-90f5-4257-b0e4-9ec8e6ce5fdc	798b2ba7-c56d-4692-8863-6c7ed546314b	2025-12-10 16:52:37.710904+00	2025-12-10 16:52:37.710904+00
6c43fef0-0602-4b07-b8a1-716d666f3cea	6926a156-9533-45dc-bcb6-b716ab914f46	75225cd3-a6a0-4188-a087-6f62f2438f21	798b2ba7-c56d-4692-8863-6c7ed546314b	2025-12-10 16:52:37.710904+00	2025-12-10 16:52:37.710904+00
dcf352dc-efee-4a3f-b766-b9c838aaae13	6926a156-9533-45dc-bcb6-b716ab914f46	44e2ca6d-bede-4487-a240-c4fc5aa2266a	798b2ba7-c56d-4692-8863-6c7ed546314b	2025-12-10 16:52:37.710904+00	2025-12-10 16:52:37.710904+00
d0a820de-e6da-4d06-a3fa-f6e6e4def13a	80af13d8-3dcd-41e6-9e1f-6932888266da	18063347-1b0e-4b21-b458-15c32b0bf751	84ed8146-c94b-4ec6-93e6-cbf7915b9d52	2025-12-10 16:49:45.972407+00	2025-12-10 16:49:45.972407+00
b1c5dda1-04dd-4237-9297-1b3e260752e0	80af13d8-3dcd-41e6-9e1f-6932888266da	1b1156ea-f6d5-43cd-9ce2-ab00d275276d	84ed8146-c94b-4ec6-93e6-cbf7915b9d52	2025-12-10 16:49:45.972407+00	2025-12-10 16:49:45.972407+00
010e392b-9536-4ce2-b7fb-12619af03b0b	80af13d8-3dcd-41e6-9e1f-6932888266da	0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	84ed8146-c94b-4ec6-93e6-cbf7915b9d52	2025-12-10 16:49:45.972407+00	2025-12-10 16:49:45.972407+00
ec4e4f5e-46f4-4476-b3a8-ecacae1d3e3d	80af13d8-3dcd-41e6-9e1f-6932888266da	8b846178-5530-4e93-97ed-c3008438e5aa	84ed8146-c94b-4ec6-93e6-cbf7915b9d52	2025-12-10 16:49:45.972407+00	2025-12-10 16:49:45.972407+00
c231611f-302f-4b12-91df-86ba5749d0c0	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	84ed8146-c94b-4ec6-93e6-cbf7915b9d52	2025-12-10 16:49:45.972407+00	2025-12-10 16:49:45.972407+00
48f83af8-970e-4429-9621-0a49d1ec2f38	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	db7bc43b-a3a6-4add-9f4a-7d19d5cfa7ee	2025-12-10 16:50:02.170782+00	2025-12-10 16:50:02.170782+00
200fdd33-f132-42ae-8ab2-04e6ba488616	1bbe551a-fa18-4df7-8897-2d15055d5c28	7fbe9247-d309-4dd9-977e-ac7c4a0bb1da	db7bc43b-a3a6-4add-9f4a-7d19d5cfa7ee	2025-12-10 16:50:02.170782+00	2025-12-10 16:50:02.170782+00
02473f08-68f4-44c7-a042-d9cbb140727e	1bbe551a-fa18-4df7-8897-2d15055d5c28	5f8dc89d-0bc0-4438-8c97-af406ff9a8df	db7bc43b-a3a6-4add-9f4a-7d19d5cfa7ee	2025-12-10 16:50:02.170782+00	2025-12-10 16:50:02.170782+00
41b90efb-ec52-4e2e-8247-702d7be776de	1bbe551a-fa18-4df7-8897-2d15055d5c28	5739a7d7-2efb-4572-83d6-0ba02ca5e5f3	db7bc43b-a3a6-4add-9f4a-7d19d5cfa7ee	2025-12-10 16:50:02.170782+00	2025-12-10 16:50:02.170782+00
3091770a-08d1-43be-afb1-c88c715663cb	1bbe551a-fa18-4df7-8897-2d15055d5c28	4b230f43-4355-44e8-9b21-47e5d0cd055b	db7bc43b-a3a6-4add-9f4a-7d19d5cfa7ee	2025-12-10 16:50:02.170782+00	2025-12-10 16:50:02.170782+00
38b055b8-863e-4070-b584-8121939e018a	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	752bcdcb-a9b5-4d9c-8d99-06b486c1a7ea	2025-12-10 16:50:36.983041+00	2025-12-10 16:50:36.983041+00
7a344ec5-9d3c-4345-a2ae-f966b3266454	1bbe551a-fa18-4df7-8897-2d15055d5c28	0a71e8da-7f00-4798-b5d6-65d062f68db3	752bcdcb-a9b5-4d9c-8d99-06b486c1a7ea	2025-12-10 16:50:36.983041+00	2025-12-10 16:50:36.983041+00
625596d3-b093-48b4-a40f-d7f26a40d73d	1bbe551a-fa18-4df7-8897-2d15055d5c28	5f8dc89d-0bc0-4438-8c97-af406ff9a8df	752bcdcb-a9b5-4d9c-8d99-06b486c1a7ea	2025-12-10 16:50:36.983041+00	2025-12-10 16:50:36.983041+00
e921ac0d-542e-4b7e-a594-6a85eb09cc2c	1bbe551a-fa18-4df7-8897-2d15055d5c28	5739a7d7-2efb-4572-83d6-0ba02ca5e5f3	752bcdcb-a9b5-4d9c-8d99-06b486c1a7ea	2025-12-10 16:50:36.983041+00	2025-12-10 16:50:36.983041+00
4d393c47-4b5a-48da-828a-bdff3474e679	1bbe551a-fa18-4df7-8897-2d15055d5c28	4b230f43-4355-44e8-9b21-47e5d0cd055b	752bcdcb-a9b5-4d9c-8d99-06b486c1a7ea	2025-12-10 16:50:36.983041+00	2025-12-10 16:50:36.983041+00
253aa39a-586d-483a-834b-05d7b24d6ac6	03ebf868-ea91-44d9-9dda-e328e13d3561	e5a8234a-2ad8-4a4b-9e55-fe99b4be6fb7	5827906c-1712-416e-8028-29c877e5c58c	2025-12-10 16:52:28.820169+00	2025-12-10 16:52:28.820169+00
4a6a1313-876d-4cbf-bc08-6dada4d71d90	03ebf868-ea91-44d9-9dda-e328e13d3561	c49c881f-d36e-41b1-992a-b60ef35b2834	5827906c-1712-416e-8028-29c877e5c58c	2025-12-10 16:52:28.820169+00	2025-12-10 16:52:28.820169+00
18e0aa2e-3756-46e6-9b14-ae212389439a	03ebf868-ea91-44d9-9dda-e328e13d3561	e60f217c-f365-419a-aa14-fbb1d6bde4c2	5827906c-1712-416e-8028-29c877e5c58c	2025-12-10 16:52:28.820169+00	2025-12-10 16:52:28.820169+00
e2a4a713-efac-42dd-97d0-314b67a533a1	03ebf868-ea91-44d9-9dda-e328e13d3561	00f7ff7e-9454-4454-b3a3-8252088b1c01	5827906c-1712-416e-8028-29c877e5c58c	2025-12-10 16:52:28.820169+00	2025-12-10 16:52:28.820169+00
8f9241ae-e431-4b0e-8e7e-63b6f5932a0b	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	5827906c-1712-416e-8028-29c877e5c58c	2025-12-10 16:52:28.820169+00	2025-12-10 16:52:28.820169+00
374385eb-31b8-4eec-a05e-a6738fb1812a	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e97bcd67-08b3-41df-a7db-9193d32e85f7	ac23d5e9-e3f0-4629-8c4f-65ad6f8a20f7	2025-12-10 16:52:28.841782+00	2025-12-10 16:52:28.841782+00
af9e45e9-c34f-41f4-8ffe-9bdb1ac194f2	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b83163fb-8646-45a0-b83e-2b387e4fc7c7	ac23d5e9-e3f0-4629-8c4f-65ad6f8a20f7	2025-12-10 16:52:28.841782+00	2025-12-10 16:52:28.841782+00
25297b62-fe40-40ca-969d-86047f82b32e	b62ee3ae-1ed9-478b-afb3-9a09473ba774	085c85c4-5455-49d8-876c-ee3a74d6d505	ac23d5e9-e3f0-4629-8c4f-65ad6f8a20f7	2025-12-10 16:52:28.841782+00	2025-12-10 16:52:28.841782+00
85285cb4-741d-4175-a1de-5ba98274e8b9	b62ee3ae-1ed9-478b-afb3-9a09473ba774	a9250f39-ec12-4f79-9bfc-89b63f6a5748	ac23d5e9-e3f0-4629-8c4f-65ad6f8a20f7	2025-12-10 16:52:28.841782+00	2025-12-10 16:52:28.841782+00
22d8aea8-a44f-4209-b12f-9134897af7c0	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e0b7ea4c-009e-4bb3-b6b6-30d5d5f73712	ac23d5e9-e3f0-4629-8c4f-65ad6f8a20f7	2025-12-10 16:52:28.841782+00	2025-12-10 16:52:28.841782+00
a14ad4df-184b-41cd-9929-5b489473711d	6926a156-9533-45dc-bcb6-b716ab914f46	baaad99a-3c3d-4a47-a089-329d457461b8	a6f82c7c-8f39-4187-a2e3-31b9e34bc778	2025-12-10 16:52:28.844098+00	2025-12-10 16:52:28.844098+00
5fd92038-a742-44d8-aec5-7613d0a2fbc9	6926a156-9533-45dc-bcb6-b716ab914f46	2537afee-2beb-4c19-89af-7ac073c1d91a	a6f82c7c-8f39-4187-a2e3-31b9e34bc778	2025-12-10 16:52:28.844098+00	2025-12-10 16:52:28.844098+00
b74f2dd1-6fb5-4e7c-af6c-6ba7e9e9a84b	6926a156-9533-45dc-bcb6-b716ab914f46	baa5eb1f-90f5-4257-b0e4-9ec8e6ce5fdc	a6f82c7c-8f39-4187-a2e3-31b9e34bc778	2025-12-10 16:52:28.844098+00	2025-12-10 16:52:28.844098+00
bf37dbc8-1292-4e58-aba3-12aa426600bf	6926a156-9533-45dc-bcb6-b716ab914f46	75225cd3-a6a0-4188-a087-6f62f2438f21	a6f82c7c-8f39-4187-a2e3-31b9e34bc778	2025-12-10 16:52:28.844098+00	2025-12-10 16:52:28.844098+00
65de52f9-5c51-4b40-913e-ca7e8aa39888	6926a156-9533-45dc-bcb6-b716ab914f46	44e2ca6d-bede-4487-a240-c4fc5aa2266a	a6f82c7c-8f39-4187-a2e3-31b9e34bc778	2025-12-10 16:52:28.844098+00	2025-12-10 16:52:28.844098+00
ed60408f-3849-45c1-86ed-e95ce5c09c95	03ebf868-ea91-44d9-9dda-e328e13d3561	e5a8234a-2ad8-4a4b-9e55-fe99b4be6fb7	ad90c18c-e444-4a8f-897a-6eafb96306a3	2025-12-10 16:52:37.676376+00	2025-12-10 16:52:37.676376+00
ba307bf3-7f53-4aff-af05-cea7807e0a24	03ebf868-ea91-44d9-9dda-e328e13d3561	c49c881f-d36e-41b1-992a-b60ef35b2834	ad90c18c-e444-4a8f-897a-6eafb96306a3	2025-12-10 16:52:37.676376+00	2025-12-10 16:52:37.676376+00
528e3066-333c-4a01-ae29-e4d930935f57	03ebf868-ea91-44d9-9dda-e328e13d3561	e60f217c-f365-419a-aa14-fbb1d6bde4c2	ad90c18c-e444-4a8f-897a-6eafb96306a3	2025-12-10 16:52:37.676376+00	2025-12-10 16:52:37.676376+00
57f9fa3c-d5e2-4a67-a516-71683b1c165e	03ebf868-ea91-44d9-9dda-e328e13d3561	00f7ff7e-9454-4454-b3a3-8252088b1c01	ad90c18c-e444-4a8f-897a-6eafb96306a3	2025-12-10 16:52:37.676376+00	2025-12-10 16:52:37.676376+00
4013d0aa-c88e-425e-9661-ddf638d7efd6	03ebf868-ea91-44d9-9dda-e328e13d3561	ea46f87b-e248-4c3b-a893-7febe2c96f21	ad90c18c-e444-4a8f-897a-6eafb96306a3	2025-12-10 16:52:37.676376+00	2025-12-10 16:52:37.676376+00
4783809e-e3f0-4c7c-bee8-d12a3d95e365	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	ad90c18c-e444-4a8f-897a-6eafb96306a3	2025-12-10 16:52:37.676376+00	2025-12-10 16:52:37.676376+00
bb9b4640-d611-4ace-a7df-c027489eb6c0	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e97bcd67-08b3-41df-a7db-9193d32e85f7	0dcc1b5a-1183-47dc-ae8c-79fa4bbe105e	2025-12-10 16:52:37.715147+00	2025-12-10 16:52:37.715147+00
99a4a3ce-2fca-4a4c-99cd-e55ab484074c	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b83163fb-8646-45a0-b83e-2b387e4fc7c7	0dcc1b5a-1183-47dc-ae8c-79fa4bbe105e	2025-12-10 16:52:37.715147+00	2025-12-10 16:52:37.715147+00
b181a761-ddbe-4010-9820-ff1709c11c6e	b62ee3ae-1ed9-478b-afb3-9a09473ba774	4a8081b9-fe3d-48e3-9e70-04d1fb92cd44	0dcc1b5a-1183-47dc-ae8c-79fa4bbe105e	2025-12-10 16:52:37.715147+00	2025-12-10 16:52:37.715147+00
3d29ab79-49b8-4965-b6e2-e86a5484ee70	b62ee3ae-1ed9-478b-afb3-9a09473ba774	085c85c4-5455-49d8-876c-ee3a74d6d505	0dcc1b5a-1183-47dc-ae8c-79fa4bbe105e	2025-12-10 16:52:37.715147+00	2025-12-10 16:52:37.715147+00
aed6bccb-c5ee-4b06-9b29-111ce708bc5f	b62ee3ae-1ed9-478b-afb3-9a09473ba774	a9250f39-ec12-4f79-9bfc-89b63f6a5748	0dcc1b5a-1183-47dc-ae8c-79fa4bbe105e	2025-12-10 16:52:37.715147+00	2025-12-10 16:52:37.715147+00
4576d68c-68db-486c-886b-36e04a90ff69	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e0b7ea4c-009e-4bb3-b6b6-30d5d5f73712	0dcc1b5a-1183-47dc-ae8c-79fa4bbe105e	2025-12-10 16:52:37.715147+00	2025-12-10 16:52:37.715147+00
59e01608-d0e9-43b2-b84c-6eeaea376566	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e97bcd67-08b3-41df-a7db-9193d32e85f7	e06c97a1-d03f-42d8-a150-b3e92ce957c9	2025-12-10 16:52:57.349473+00	2025-12-10 16:52:57.349473+00
60a813c6-d0d1-4170-81e2-ed290510b311	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b83163fb-8646-45a0-b83e-2b387e4fc7c7	e06c97a1-d03f-42d8-a150-b3e92ce957c9	2025-12-10 16:52:57.349473+00	2025-12-10 16:52:57.349473+00
45345bb6-8b01-4b4c-bc4d-d2b187c84466	b62ee3ae-1ed9-478b-afb3-9a09473ba774	4a8081b9-fe3d-48e3-9e70-04d1fb92cd44	e06c97a1-d03f-42d8-a150-b3e92ce957c9	2025-12-10 16:52:57.349473+00	2025-12-10 16:52:57.349473+00
5059ae27-8b57-4839-a2eb-d8e2beea231a	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	e06c97a1-d03f-42d8-a150-b3e92ce957c9	2025-12-10 16:52:57.349473+00	2025-12-10 16:52:57.349473+00
00b1fe19-41f1-438b-a918-2e7f47d1a7fb	b62ee3ae-1ed9-478b-afb3-9a09473ba774	a9250f39-ec12-4f79-9bfc-89b63f6a5748	e06c97a1-d03f-42d8-a150-b3e92ce957c9	2025-12-10 16:52:57.349473+00	2025-12-10 16:52:57.349473+00
f56eac33-3294-4032-8a4b-d231c024169e	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e0b7ea4c-009e-4bb3-b6b6-30d5d5f73712	e06c97a1-d03f-42d8-a150-b3e92ce957c9	2025-12-10 16:52:57.349473+00	2025-12-10 16:52:57.349473+00
0ebdfe5d-9264-468b-979e-597632499677	6926a156-9533-45dc-bcb6-b716ab914f46	4d106f8b-5fa9-497e-bc2e-7439e78c12a1	912e0433-5fa7-41b9-b033-f41af15e5021	2025-12-10 16:52:58.040105+00	2025-12-10 16:52:58.040105+00
80ca1e93-cd00-4877-b61e-19beef560339	6926a156-9533-45dc-bcb6-b716ab914f46	baaad99a-3c3d-4a47-a089-329d457461b8	912e0433-5fa7-41b9-b033-f41af15e5021	2025-12-10 16:52:58.040105+00	2025-12-10 16:52:58.040105+00
b51a38e2-ee2b-4b32-a12c-bc64b4d51822	6926a156-9533-45dc-bcb6-b716ab914f46	2537afee-2beb-4c19-89af-7ac073c1d91a	912e0433-5fa7-41b9-b033-f41af15e5021	2025-12-10 16:52:58.040105+00	2025-12-10 16:52:58.040105+00
1c217ef0-bb3b-488e-a21a-a21139a2876a	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	912e0433-5fa7-41b9-b033-f41af15e5021	2025-12-10 16:52:58.040105+00	2025-12-10 16:52:58.040105+00
1b65ecc7-3e91-48ae-bc5a-7f014b9b5e7f	6926a156-9533-45dc-bcb6-b716ab914f46	75225cd3-a6a0-4188-a087-6f62f2438f21	912e0433-5fa7-41b9-b033-f41af15e5021	2025-12-10 16:52:58.040105+00	2025-12-10 16:52:58.040105+00
505b3839-1736-41fa-9163-fd6dc329a1f0	6926a156-9533-45dc-bcb6-b716ab914f46	44e2ca6d-bede-4487-a240-c4fc5aa2266a	912e0433-5fa7-41b9-b033-f41af15e5021	2025-12-10 16:52:58.040105+00	2025-12-10 16:52:58.040105+00
f1e0778a-fa69-4038-a404-04d24aee5c6c	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e97bcd67-08b3-41df-a7db-9193d32e85f7	4830be76-5d56-471f-a0b7-48b9e0317378	2025-12-10 16:53:10.401875+00	2025-12-10 16:53:10.401875+00
754b92c0-ec23-4695-8fb5-bd58bfb7d5c8	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b83163fb-8646-45a0-b83e-2b387e4fc7c7	4830be76-5d56-471f-a0b7-48b9e0317378	2025-12-10 16:53:10.401875+00	2025-12-10 16:53:10.401875+00
fad785e7-e4d8-45d3-8cff-c37dc57cb999	b62ee3ae-1ed9-478b-afb3-9a09473ba774	4a8081b9-fe3d-48e3-9e70-04d1fb92cd44	4830be76-5d56-471f-a0b7-48b9e0317378	2025-12-10 16:53:10.401875+00	2025-12-10 16:53:10.401875+00
28524338-7941-4c25-8b7a-2b4c0d4bc37e	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	4830be76-5d56-471f-a0b7-48b9e0317378	2025-12-10 16:53:10.401875+00	2025-12-10 16:53:10.401875+00
c50935b1-89b4-476f-bff0-ba546e7f9aa0	b62ee3ae-1ed9-478b-afb3-9a09473ba774	3fcb535d-b307-4f13-b04d-28565c934215	4830be76-5d56-471f-a0b7-48b9e0317378	2025-12-10 16:53:10.401875+00	2025-12-10 16:53:10.401875+00
14f6a32e-2a2e-4499-bc7f-89b58ad6fbf4	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e0b7ea4c-009e-4bb3-b6b6-30d5d5f73712	4830be76-5d56-471f-a0b7-48b9e0317378	2025-12-10 16:53:10.401875+00	2025-12-10 16:53:10.401875+00
f3481235-9efa-4898-bdaf-282a5074a65b	6926a156-9533-45dc-bcb6-b716ab914f46	4d106f8b-5fa9-497e-bc2e-7439e78c12a1	a0cac501-ec7b-4a6e-8895-72b4b95d49f8	2025-12-10 16:53:11.619565+00	2025-12-10 16:53:11.619565+00
b1e0119f-a169-44c1-9761-406eac3f263d	6926a156-9533-45dc-bcb6-b716ab914f46	baaad99a-3c3d-4a47-a089-329d457461b8	a0cac501-ec7b-4a6e-8895-72b4b95d49f8	2025-12-10 16:53:11.619565+00	2025-12-10 16:53:11.619565+00
2b3185ea-6d47-482c-83c5-5c74769e1349	6926a156-9533-45dc-bcb6-b716ab914f46	2537afee-2beb-4c19-89af-7ac073c1d91a	a0cac501-ec7b-4a6e-8895-72b4b95d49f8	2025-12-10 16:53:11.619565+00	2025-12-10 16:53:11.619565+00
6c0561fb-4856-4ba5-b3f5-43f3c5f688dd	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	a0cac501-ec7b-4a6e-8895-72b4b95d49f8	2025-12-10 16:53:11.619565+00	2025-12-10 16:53:11.619565+00
0373d768-79af-42e7-893e-7662ec67f73e	6926a156-9533-45dc-bcb6-b716ab914f46	75225cd3-a6a0-4188-a087-6f62f2438f21	a0cac501-ec7b-4a6e-8895-72b4b95d49f8	2025-12-10 16:53:11.619565+00	2025-12-10 16:53:11.619565+00
0a167ac4-441a-4be1-a409-4f606d761573	6926a156-9533-45dc-bcb6-b716ab914f46	5b61ccba-92ce-4b63-a213-9bf8e2065217	a0cac501-ec7b-4a6e-8895-72b4b95d49f8	2025-12-10 16:53:11.619565+00	2025-12-10 16:53:11.619565+00
e025126c-ff2b-4365-9185-7ea8db13c18b	03ebf868-ea91-44d9-9dda-e328e13d3561	228dee0e-30a5-4f47-b69b-98a1891c3eea	89211f2f-1a7e-4ee6-b81c-2ed7af5e6f09	2025-12-10 16:54:10.137534+00	2025-12-10 16:54:10.137534+00
1d69da3a-515b-4313-ac51-06b1465eb6ce	03ebf868-ea91-44d9-9dda-e328e13d3561	6dd8d52d-0e35-4fbc-9f20-4831d8b8dc56	89211f2f-1a7e-4ee6-b81c-2ed7af5e6f09	2025-12-10 16:54:10.137534+00	2025-12-10 16:54:10.137534+00
58fa6422-a993-4400-9166-2d179d3f15c3	03ebf868-ea91-44d9-9dda-e328e13d3561	e60f217c-f365-419a-aa14-fbb1d6bde4c2	89211f2f-1a7e-4ee6-b81c-2ed7af5e6f09	2025-12-10 16:54:10.137534+00	2025-12-10 16:54:10.137534+00
74776436-1281-4aee-8b5a-04275f57a8d9	03ebf868-ea91-44d9-9dda-e328e13d3561	3c37a771-a3fc-4e48-a653-cad97d644ae8	89211f2f-1a7e-4ee6-b81c-2ed7af5e6f09	2025-12-10 16:54:10.137534+00	2025-12-10 16:54:10.137534+00
22958155-a411-4a6c-ade8-f608b87efccf	03ebf868-ea91-44d9-9dda-e328e13d3561	ea46f87b-e248-4c3b-a893-7febe2c96f21	89211f2f-1a7e-4ee6-b81c-2ed7af5e6f09	2025-12-10 16:54:10.137534+00	2025-12-10 16:54:10.137534+00
e4cf2dcc-9b3c-43e2-9299-bedda3fb9c10	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	89211f2f-1a7e-4ee6-b81c-2ed7af5e6f09	2025-12-10 16:54:10.137534+00	2025-12-10 16:54:10.137534+00
6de740ec-8471-40fc-8624-b561576f2de4	03ebf868-ea91-44d9-9dda-e328e13d3561	e5a8234a-2ad8-4a4b-9e55-fe99b4be6fb7	d899ca8c-824f-4346-a08b-f3127a3b2732	2025-12-10 16:53:11.174062+00	2025-12-10 16:53:11.174062+00
127633d0-3e1a-4018-8be8-8f97e89f2f98	03ebf868-ea91-44d9-9dda-e328e13d3561	c49c881f-d36e-41b1-992a-b60ef35b2834	d899ca8c-824f-4346-a08b-f3127a3b2732	2025-12-10 16:53:11.174062+00	2025-12-10 16:53:11.174062+00
f8731e0e-dd57-49fb-baa8-5d44df1b8e03	03ebf868-ea91-44d9-9dda-e328e13d3561	e60f217c-f365-419a-aa14-fbb1d6bde4c2	d899ca8c-824f-4346-a08b-f3127a3b2732	2025-12-10 16:53:11.174062+00	2025-12-10 16:53:11.174062+00
32af3428-2658-469d-ae45-da3997cf3b82	03ebf868-ea91-44d9-9dda-e328e13d3561	3c37a771-a3fc-4e48-a653-cad97d644ae8	d899ca8c-824f-4346-a08b-f3127a3b2732	2025-12-10 16:53:11.174062+00	2025-12-10 16:53:11.174062+00
c4f77ecb-97b0-4f16-a32f-12c1b1e2a409	03ebf868-ea91-44d9-9dda-e328e13d3561	ea46f87b-e248-4c3b-a893-7febe2c96f21	d899ca8c-824f-4346-a08b-f3127a3b2732	2025-12-10 16:53:11.174062+00	2025-12-10 16:53:11.174062+00
c92b7ced-91b4-43f0-8d7c-09e078a324b3	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	d899ca8c-824f-4346-a08b-f3127a3b2732	2025-12-10 16:53:11.174062+00	2025-12-10 16:53:11.174062+00
ee00bb2f-8bdf-4974-b494-f5dec2b8905d	6926a156-9533-45dc-bcb6-b716ab914f46	4d106f8b-5fa9-497e-bc2e-7439e78c12a1	535e0eac-e48c-4955-aafd-08e1dafb0cf5	2025-12-10 16:53:26.42627+00	2025-12-10 16:53:26.42627+00
0ea94c80-541d-45e9-a652-9136449d2eb6	6926a156-9533-45dc-bcb6-b716ab914f46	baaad99a-3c3d-4a47-a089-329d457461b8	535e0eac-e48c-4955-aafd-08e1dafb0cf5	2025-12-10 16:53:26.42627+00	2025-12-10 16:53:26.42627+00
9fafe9da-e1bc-4338-a1bb-2f6e68343950	6926a156-9533-45dc-bcb6-b716ab914f46	733de489-0836-4d59-ac47-0c82344d3c1f	535e0eac-e48c-4955-aafd-08e1dafb0cf5	2025-12-10 16:53:26.42627+00	2025-12-10 16:53:26.42627+00
b6bfbfc0-377d-482a-bded-e6de2ece27c8	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	535e0eac-e48c-4955-aafd-08e1dafb0cf5	2025-12-10 16:53:26.42627+00	2025-12-10 16:53:26.42627+00
5797bcfa-037a-4258-a5ef-e5e1e33dd547	6926a156-9533-45dc-bcb6-b716ab914f46	75225cd3-a6a0-4188-a087-6f62f2438f21	535e0eac-e48c-4955-aafd-08e1dafb0cf5	2025-12-10 16:53:26.42627+00	2025-12-10 16:53:26.42627+00
492ce74b-ebaa-4395-953b-8f607433f1c6	6926a156-9533-45dc-bcb6-b716ab914f46	5b61ccba-92ce-4b63-a213-9bf8e2065217	535e0eac-e48c-4955-aafd-08e1dafb0cf5	2025-12-10 16:53:26.42627+00	2025-12-10 16:53:26.42627+00
bf1a9cad-9fcd-4185-893a-8601aff1e16b	6926a156-9533-45dc-bcb6-b716ab914f46	4d106f8b-5fa9-497e-bc2e-7439e78c12a1	88301ebf-b8d5-4ca6-88c0-6adb5af10a43	2025-12-10 16:53:55.316768+00	2025-12-10 16:53:55.316768+00
8872d7f1-765b-455e-9e47-827460bfad1f	6926a156-9533-45dc-bcb6-b716ab914f46	baaad99a-3c3d-4a47-a089-329d457461b8	88301ebf-b8d5-4ca6-88c0-6adb5af10a43	2025-12-10 16:53:55.316768+00	2025-12-10 16:53:55.316768+00
53a64e5c-9746-4b24-afbf-d72e6740be77	6926a156-9533-45dc-bcb6-b716ab914f46	733de489-0836-4d59-ac47-0c82344d3c1f	88301ebf-b8d5-4ca6-88c0-6adb5af10a43	2025-12-10 16:53:55.316768+00	2025-12-10 16:53:55.316768+00
b264011e-c8c7-4000-a26d-9baebd9a5cf6	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	88301ebf-b8d5-4ca6-88c0-6adb5af10a43	2025-12-10 16:53:55.316768+00	2025-12-10 16:53:55.316768+00
ff85dc0a-e0e4-4596-9856-7bcb50599ffb	6926a156-9533-45dc-bcb6-b716ab914f46	0acc4a3f-ed6b-464b-b6be-4b0038eb0868	88301ebf-b8d5-4ca6-88c0-6adb5af10a43	2025-12-10 16:53:55.316768+00	2025-12-10 16:53:55.316768+00
72361e28-1991-41c7-bd94-9f4621f5440c	6926a156-9533-45dc-bcb6-b716ab914f46	5b61ccba-92ce-4b63-a213-9bf8e2065217	88301ebf-b8d5-4ca6-88c0-6adb5af10a43	2025-12-10 16:53:55.316768+00	2025-12-10 16:53:55.316768+00
acabce63-59a3-4dd4-af30-57678b91d60c	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b311ef39-43ad-4f53-9883-bdf1f942ace4	3dea9793-cf58-4f7b-9b6a-8430235d24cb	2025-12-10 16:54:09.627037+00	2025-12-10 16:54:09.627037+00
54d59aeb-b03c-4e30-bc81-ad483ca8edfd	b62ee3ae-1ed9-478b-afb3-9a09473ba774	812d243e-9063-4b61-8616-67904ceeb1fb	3dea9793-cf58-4f7b-9b6a-8430235d24cb	2025-12-10 16:54:09.627037+00	2025-12-10 16:54:09.627037+00
43fbc743-ce85-48e2-8141-58a779deac6f	b62ee3ae-1ed9-478b-afb3-9a09473ba774	4a8081b9-fe3d-48e3-9e70-04d1fb92cd44	3dea9793-cf58-4f7b-9b6a-8430235d24cb	2025-12-10 16:54:09.627037+00	2025-12-10 16:54:09.627037+00
25a8b5f3-e85b-45d9-8c69-aa9d85d428ec	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	3dea9793-cf58-4f7b-9b6a-8430235d24cb	2025-12-10 16:54:09.627037+00	2025-12-10 16:54:09.627037+00
e4c3f36d-586f-473f-ac36-bc8ba0000730	b62ee3ae-1ed9-478b-afb3-9a09473ba774	3fcb535d-b307-4f13-b04d-28565c934215	3dea9793-cf58-4f7b-9b6a-8430235d24cb	2025-12-10 16:54:09.627037+00	2025-12-10 16:54:09.627037+00
1e29e1c2-06d4-4cc0-9ee4-7419c7908a50	b62ee3ae-1ed9-478b-afb3-9a09473ba774	f4f87859-83e2-49b7-b9f3-7d2b698bf1da	3dea9793-cf58-4f7b-9b6a-8430235d24cb	2025-12-10 16:54:09.627037+00	2025-12-10 16:54:09.627037+00
e446dbdf-1568-4fb7-b9da-77e52393e28c	6926a156-9533-45dc-bcb6-b716ab914f46	4d106f8b-5fa9-497e-bc2e-7439e78c12a1	323166e4-0fb0-4979-a69e-b60e56cb84dd	2025-12-10 16:54:10.595654+00	2025-12-10 16:54:10.595654+00
4a8ecb75-b133-4786-986c-224cfa0d06b1	6926a156-9533-45dc-bcb6-b716ab914f46	7ccbf85d-5fff-454f-974a-32319f6d2d7d	323166e4-0fb0-4979-a69e-b60e56cb84dd	2025-12-10 16:54:10.595654+00	2025-12-10 16:54:10.595654+00
865179d0-1a14-4d3c-a002-25ccd7c989ff	6926a156-9533-45dc-bcb6-b716ab914f46	733de489-0836-4d59-ac47-0c82344d3c1f	323166e4-0fb0-4979-a69e-b60e56cb84dd	2025-12-10 16:54:10.595654+00	2025-12-10 16:54:10.595654+00
fdabbbd8-ae1c-4e8a-a4a2-4a3245b37208	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	323166e4-0fb0-4979-a69e-b60e56cb84dd	2025-12-10 16:54:10.595654+00	2025-12-10 16:54:10.595654+00
62076f9f-0202-4317-8bdd-798989a24bf6	6926a156-9533-45dc-bcb6-b716ab914f46	0acc4a3f-ed6b-464b-b6be-4b0038eb0868	323166e4-0fb0-4979-a69e-b60e56cb84dd	2025-12-10 16:54:10.595654+00	2025-12-10 16:54:10.595654+00
3130fe3b-2156-4e25-9a12-54bb6e748487	6926a156-9533-45dc-bcb6-b716ab914f46	5b61ccba-92ce-4b63-a213-9bf8e2065217	323166e4-0fb0-4979-a69e-b60e56cb84dd	2025-12-10 16:54:10.595654+00	2025-12-10 16:54:10.595654+00
8aa4edef-fb7d-4f7b-9341-b45b31b6e928	03ebf868-ea91-44d9-9dda-e328e13d3561	228dee0e-30a5-4f47-b69b-98a1891c3eea	0b1195b2-2af2-497f-8390-777c46d938ea	2025-12-10 16:54:24.093831+00	2025-12-10 16:54:24.093831+00
42311c0b-818d-44aa-976b-21988ea93981	03ebf868-ea91-44d9-9dda-e328e13d3561	6dd8d52d-0e35-4fbc-9f20-4831d8b8dc56	0b1195b2-2af2-497f-8390-777c46d938ea	2025-12-10 16:54:24.093831+00	2025-12-10 16:54:24.093831+00
c8a77902-f082-476f-8346-88c7d7e19b50	03ebf868-ea91-44d9-9dda-e328e13d3561	e60f217c-f365-419a-aa14-fbb1d6bde4c2	0b1195b2-2af2-497f-8390-777c46d938ea	2025-12-10 16:54:24.093831+00	2025-12-10 16:54:24.093831+00
403890ee-4f9a-4270-982b-19be85fe7493	03ebf868-ea91-44d9-9dda-e328e13d3561	3c37a771-a3fc-4e48-a653-cad97d644ae8	0b1195b2-2af2-497f-8390-777c46d938ea	2025-12-10 16:54:24.093831+00	2025-12-10 16:54:24.093831+00
1ec9b88f-bf84-4d56-b2e7-137f1b7ee7d7	03ebf868-ea91-44d9-9dda-e328e13d3561	a6d74d18-9a03-4141-a8bf-80848754bec0	0b1195b2-2af2-497f-8390-777c46d938ea	2025-12-10 16:54:24.093831+00	2025-12-10 16:54:24.093831+00
f6996fe6-24a2-4627-9947-24786df1e102	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	0b1195b2-2af2-497f-8390-777c46d938ea	2025-12-10 16:54:24.093831+00	2025-12-10 16:54:24.093831+00
b9e997f1-1ea2-4f83-bba9-a1aa0520b6b6	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e97bcd67-08b3-41df-a7db-9193d32e85f7	51390b37-1c56-449b-ab7b-915887ff17b8	2025-12-10 16:53:27.088316+00	2025-12-10 16:53:27.088316+00
e65717fa-1635-47f0-b49e-60d275d9dee8	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b83163fb-8646-45a0-b83e-2b387e4fc7c7	51390b37-1c56-449b-ab7b-915887ff17b8	2025-12-10 16:53:27.088316+00	2025-12-10 16:53:27.088316+00
cab9821b-83fc-4403-aa7d-5c3a71e12c73	b62ee3ae-1ed9-478b-afb3-9a09473ba774	4a8081b9-fe3d-48e3-9e70-04d1fb92cd44	51390b37-1c56-449b-ab7b-915887ff17b8	2025-12-10 16:53:27.088316+00	2025-12-10 16:53:27.088316+00
f139945c-c337-4891-b1e7-58e562761742	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	51390b37-1c56-449b-ab7b-915887ff17b8	2025-12-10 16:53:27.088316+00	2025-12-10 16:53:27.088316+00
831ca61d-b935-42b3-9743-f8ee15ae2f7c	b62ee3ae-1ed9-478b-afb3-9a09473ba774	3fcb535d-b307-4f13-b04d-28565c934215	51390b37-1c56-449b-ab7b-915887ff17b8	2025-12-10 16:53:27.088316+00	2025-12-10 16:53:27.088316+00
8dc1853b-60b6-4fcc-bbff-c98c889700e0	b62ee3ae-1ed9-478b-afb3-9a09473ba774	f4f87859-83e2-49b7-b9f3-7d2b698bf1da	51390b37-1c56-449b-ab7b-915887ff17b8	2025-12-10 16:53:27.088316+00	2025-12-10 16:53:27.088316+00
2903b8aa-13e8-4b18-abeb-e2984573e7a9	b62ee3ae-1ed9-478b-afb3-9a09473ba774	e97bcd67-08b3-41df-a7db-9193d32e85f7	1dfe70fa-5610-4586-848a-2e24fa93fcf1	2025-12-10 16:53:54.395218+00	2025-12-10 16:53:54.395218+00
7f66b51f-7b0a-4485-85b6-0c8f2bdc9b10	b62ee3ae-1ed9-478b-afb3-9a09473ba774	812d243e-9063-4b61-8616-67904ceeb1fb	1dfe70fa-5610-4586-848a-2e24fa93fcf1	2025-12-10 16:53:54.395218+00	2025-12-10 16:53:54.395218+00
d65d98ce-0f58-42aa-b1f2-99d7072adba2	b62ee3ae-1ed9-478b-afb3-9a09473ba774	4a8081b9-fe3d-48e3-9e70-04d1fb92cd44	1dfe70fa-5610-4586-848a-2e24fa93fcf1	2025-12-10 16:53:54.395218+00	2025-12-10 16:53:54.395218+00
43bc7e17-ac39-41c0-920c-596f55f13381	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	1dfe70fa-5610-4586-848a-2e24fa93fcf1	2025-12-10 16:53:54.395218+00	2025-12-10 16:53:54.395218+00
8a2df672-616c-4c58-81f1-2236a6d74ba4	b62ee3ae-1ed9-478b-afb3-9a09473ba774	3fcb535d-b307-4f13-b04d-28565c934215	1dfe70fa-5610-4586-848a-2e24fa93fcf1	2025-12-10 16:53:54.395218+00	2025-12-10 16:53:54.395218+00
b638c5b7-bc7c-4f4a-b5ce-9c6c8c0950b3	b62ee3ae-1ed9-478b-afb3-9a09473ba774	f4f87859-83e2-49b7-b9f3-7d2b698bf1da	1dfe70fa-5610-4586-848a-2e24fa93fcf1	2025-12-10 16:53:54.395218+00	2025-12-10 16:53:54.395218+00
d997226c-3a11-44f8-9568-b9c9418927de	03ebf868-ea91-44d9-9dda-e328e13d3561	228dee0e-30a5-4f47-b69b-98a1891c3eea	0ff35def-bea0-4650-b381-7e08a9c6a894	2025-12-10 16:53:54.898697+00	2025-12-10 16:53:54.898697+00
8881759a-b941-4dd5-81b7-99fbdc1bd874	03ebf868-ea91-44d9-9dda-e328e13d3561	c49c881f-d36e-41b1-992a-b60ef35b2834	0ff35def-bea0-4650-b381-7e08a9c6a894	2025-12-10 16:53:54.898697+00	2025-12-10 16:53:54.898697+00
a8202041-412e-440f-ab11-3f577dd3d7ef	03ebf868-ea91-44d9-9dda-e328e13d3561	e60f217c-f365-419a-aa14-fbb1d6bde4c2	0ff35def-bea0-4650-b381-7e08a9c6a894	2025-12-10 16:53:54.898697+00	2025-12-10 16:53:54.898697+00
3c90931c-0d41-4079-9905-5ac2d942a668	03ebf868-ea91-44d9-9dda-e328e13d3561	3c37a771-a3fc-4e48-a653-cad97d644ae8	0ff35def-bea0-4650-b381-7e08a9c6a894	2025-12-10 16:53:54.898697+00	2025-12-10 16:53:54.898697+00
2043ce50-87f7-4049-a7d5-64bcb48000e2	03ebf868-ea91-44d9-9dda-e328e13d3561	ea46f87b-e248-4c3b-a893-7febe2c96f21	0ff35def-bea0-4650-b381-7e08a9c6a894	2025-12-10 16:53:54.898697+00	2025-12-10 16:53:54.898697+00
c53c5b54-b900-4962-aa01-4fc3fa9b5b11	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	0ff35def-bea0-4650-b381-7e08a9c6a894	2025-12-10 16:53:54.898697+00	2025-12-10 16:53:54.898697+00
b2179a89-5f5e-43dd-8a3e-9db945b31b8b	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b311ef39-43ad-4f53-9883-bdf1f942ace4	c8f2930f-d8a1-40e8-a01d-f8eb4a72ddac	2025-12-10 16:54:23.432763+00	2025-12-10 16:54:23.432763+00
b17850bd-2921-441e-b3dc-1416d1c6e6f7	b62ee3ae-1ed9-478b-afb3-9a09473ba774	812d243e-9063-4b61-8616-67904ceeb1fb	c8f2930f-d8a1-40e8-a01d-f8eb4a72ddac	2025-12-10 16:54:23.432763+00	2025-12-10 16:54:23.432763+00
9cca3f9f-7825-40f3-ab61-6169632adddb	b62ee3ae-1ed9-478b-afb3-9a09473ba774	60fdb01d-3d08-4d79-81d2-d069c9a711ec	c8f2930f-d8a1-40e8-a01d-f8eb4a72ddac	2025-12-10 16:54:23.432763+00	2025-12-10 16:54:23.432763+00
19578263-e8e3-490e-9f5a-ba44ccfa7f3b	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	c8f2930f-d8a1-40e8-a01d-f8eb4a72ddac	2025-12-10 16:54:23.432763+00	2025-12-10 16:54:23.432763+00
891ad209-03f8-442b-8365-b71a7302d835	b62ee3ae-1ed9-478b-afb3-9a09473ba774	3fcb535d-b307-4f13-b04d-28565c934215	c8f2930f-d8a1-40e8-a01d-f8eb4a72ddac	2025-12-10 16:54:23.432763+00	2025-12-10 16:54:23.432763+00
35c5fd63-e4a6-4785-b6b9-bc3b76fa8341	b62ee3ae-1ed9-478b-afb3-9a09473ba774	f4f87859-83e2-49b7-b9f3-7d2b698bf1da	c8f2930f-d8a1-40e8-a01d-f8eb4a72ddac	2025-12-10 16:54:23.432763+00	2025-12-10 16:54:23.432763+00
3a52fb88-1bcc-4a09-9d2f-d6d1664106c0	6926a156-9533-45dc-bcb6-b716ab914f46	f2d748f8-44cc-4a61-8cb6-fa2af3bb4b1b	7d4f967d-0c36-405d-93ce-f66c828ed81d	2025-12-10 16:54:26.229685+00	2025-12-10 16:54:26.229685+00
d3992656-9906-4b68-a6a8-e02e9a1aad33	6926a156-9533-45dc-bcb6-b716ab914f46	7ccbf85d-5fff-454f-974a-32319f6d2d7d	7d4f967d-0c36-405d-93ce-f66c828ed81d	2025-12-10 16:54:26.229685+00	2025-12-10 16:54:26.229685+00
65e2596b-7de0-415b-a6e9-47e8cd405407	6926a156-9533-45dc-bcb6-b716ab914f46	733de489-0836-4d59-ac47-0c82344d3c1f	7d4f967d-0c36-405d-93ce-f66c828ed81d	2025-12-10 16:54:26.229685+00	2025-12-10 16:54:26.229685+00
d8cd1beb-4fb6-4ce7-abda-847a5ccc8236	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	7d4f967d-0c36-405d-93ce-f66c828ed81d	2025-12-10 16:54:26.229685+00	2025-12-10 16:54:26.229685+00
8ac1cb5c-a3f3-4dd0-9dfc-9366042d5343	6926a156-9533-45dc-bcb6-b716ab914f46	0acc4a3f-ed6b-464b-b6be-4b0038eb0868	7d4f967d-0c36-405d-93ce-f66c828ed81d	2025-12-10 16:54:26.229685+00	2025-12-10 16:54:26.229685+00
c4a47600-5b3b-4f8e-83b5-724da0e0967e	6926a156-9533-45dc-bcb6-b716ab914f46	5b61ccba-92ce-4b63-a213-9bf8e2065217	7d4f967d-0c36-405d-93ce-f66c828ed81d	2025-12-10 16:54:26.229685+00	2025-12-10 16:54:26.229685+00
23c4e68a-b1a6-429c-bdcb-923d22dd36c8	03ebf868-ea91-44d9-9dda-e328e13d3561	228dee0e-30a5-4f47-b69b-98a1891c3eea	28deac9b-9120-47ba-b5a3-d843104c3664	2025-12-10 17:03:42.161447+00	2025-12-10 17:03:42.161447+00
b40f6ea9-b4b9-49a0-9570-ec2add48d5cb	03ebf868-ea91-44d9-9dda-e328e13d3561	6dd8d52d-0e35-4fbc-9f20-4831d8b8dc56	28deac9b-9120-47ba-b5a3-d843104c3664	2025-12-10 17:03:42.161447+00	2025-12-10 17:03:42.161447+00
0a75ba5a-5bd2-44b6-af6c-71f52948bb56	03ebf868-ea91-44d9-9dda-e328e13d3561	14a676d1-bad9-4ec8-a646-f2201b7ae675	28deac9b-9120-47ba-b5a3-d843104c3664	2025-12-10 17:03:42.161447+00	2025-12-10 17:03:42.161447+00
2de28287-8f63-47a9-89fc-a150dbc3bdb7	03ebf868-ea91-44d9-9dda-e328e13d3561	3c37a771-a3fc-4e48-a653-cad97d644ae8	28deac9b-9120-47ba-b5a3-d843104c3664	2025-12-10 17:03:42.161447+00	2025-12-10 17:03:42.161447+00
686a7486-8c24-4cc7-9b56-2b14d651e535	03ebf868-ea91-44d9-9dda-e328e13d3561	a6d74d18-9a03-4141-a8bf-80848754bec0	28deac9b-9120-47ba-b5a3-d843104c3664	2025-12-10 17:03:42.161447+00	2025-12-10 17:03:42.161447+00
56bc4ecb-1de8-46dd-b3c7-f15e259e5138	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	28deac9b-9120-47ba-b5a3-d843104c3664	2025-12-10 17:03:42.161447+00	2025-12-10 17:03:42.161447+00
3fd872ce-7a3b-4370-a7c5-c6d032a423cd	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	de1e1f92-9460-451e-bd00-1f146233dbe5	2025-12-10 17:03:47.580452+00	2025-12-10 17:03:47.580452+00
bc4b96bd-0564-4015-9082-904a3f957d03	82732d9d-904b-4f60-bc34-dbd6dfd85b97	28de0554-fd24-4bd4-b056-2000640e9b1c	de1e1f92-9460-451e-bd00-1f146233dbe5	2025-12-10 17:03:47.580452+00	2025-12-10 17:03:47.580452+00
27c1b105-f425-42c3-ab43-8ea25f209e2b	82732d9d-904b-4f60-bc34-dbd6dfd85b97	76440291-a906-49bf-916e-e5330f8e8d67	de1e1f92-9460-451e-bd00-1f146233dbe5	2025-12-10 17:03:47.580452+00	2025-12-10 17:03:47.580452+00
a248c9ff-67de-4838-9bf1-285708634d06	82732d9d-904b-4f60-bc34-dbd6dfd85b97	062227e3-a61f-4acf-8799-0afc8423d095	de1e1f92-9460-451e-bd00-1f146233dbe5	2025-12-10 17:03:47.580452+00	2025-12-10 17:03:47.580452+00
8ec7da3a-2e2b-43b5-92c2-b87eda0d29ec	82732d9d-904b-4f60-bc34-dbd6dfd85b97	3b3f78a8-2e0f-4c52-90a3-66ba42fadb1c	de1e1f92-9460-451e-bd00-1f146233dbe5	2025-12-10 17:03:47.580452+00	2025-12-10 17:03:47.580452+00
410b99bc-f0db-43b6-959f-e12ea5a20dbf	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	7858091a-9b9e-4eaf-babf-d4912ed27475	2025-12-10 17:03:48.260476+00	2025-12-10 17:03:48.260476+00
97d302cd-6138-4f11-8bf0-bed7f85ab089	80af13d8-3dcd-41e6-9e1f-6932888266da	18063347-1b0e-4b21-b458-15c32b0bf751	7858091a-9b9e-4eaf-babf-d4912ed27475	2025-12-10 17:03:48.260476+00	2025-12-10 17:03:48.260476+00
c7c753af-995d-4a4b-9733-3f3a9f30e1c1	80af13d8-3dcd-41e6-9e1f-6932888266da	1b1156ea-f6d5-43cd-9ce2-ab00d275276d	7858091a-9b9e-4eaf-babf-d4912ed27475	2025-12-10 17:03:48.260476+00	2025-12-10 17:03:48.260476+00
8388509d-44f0-47e4-97e8-710258c65ad7	80af13d8-3dcd-41e6-9e1f-6932888266da	846f2df7-caef-4a9a-adc8-218001827c98	7858091a-9b9e-4eaf-babf-d4912ed27475	2025-12-10 17:03:48.260476+00	2025-12-10 17:03:48.260476+00
f3394785-463a-4d9b-9017-bec2e1506f9b	80af13d8-3dcd-41e6-9e1f-6932888266da	606aeb70-e94c-4b92-9685-b082d8554fdd	7858091a-9b9e-4eaf-babf-d4912ed27475	2025-12-10 17:03:48.260476+00	2025-12-10 17:03:48.260476+00
a47e0d0a-3b24-4524-a72e-4b866c9a8056	82732d9d-904b-4f60-bc34-dbd6dfd85b97	7f595c63-cdae-45cf-890f-70db55d8a7b7	fffe9ee2-7f55-43c7-888e-0aaf83d46984	2025-12-10 17:03:58.899477+00	2025-12-10 17:03:58.899477+00
bd1a4540-a2c3-4320-ae57-cb61528bace1	82732d9d-904b-4f60-bc34-dbd6dfd85b97	76440291-a906-49bf-916e-e5330f8e8d67	fffe9ee2-7f55-43c7-888e-0aaf83d46984	2025-12-10 17:03:58.899477+00	2025-12-10 17:03:58.899477+00
f22c8b2c-c453-4ebb-b56f-e0f01a352977	82732d9d-904b-4f60-bc34-dbd6dfd85b97	062227e3-a61f-4acf-8799-0afc8423d095	fffe9ee2-7f55-43c7-888e-0aaf83d46984	2025-12-10 17:03:58.899477+00	2025-12-10 17:03:58.899477+00
43e851af-8380-4304-9446-6c19ac9b46b4	82732d9d-904b-4f60-bc34-dbd6dfd85b97	3b3f78a8-2e0f-4c52-90a3-66ba42fadb1c	fffe9ee2-7f55-43c7-888e-0aaf83d46984	2025-12-10 17:03:58.899477+00	2025-12-10 17:03:58.899477+00
f6cda2f6-4296-45c3-9570-0c86833a1358	82732d9d-904b-4f60-bc34-dbd6dfd85b97	a2a57311-abc8-4f99-96ff-53c140a26019	fffe9ee2-7f55-43c7-888e-0aaf83d46984	2025-12-10 17:03:58.899477+00	2025-12-10 17:03:58.899477+00
68c5c835-fed0-4070-b454-11bcf0ef1fe4	80af13d8-3dcd-41e6-9e1f-6932888266da	036235bc-d8c7-496e-a1cc-b868312ad351	abcc11c8-855f-4524-8862-4100d24e0bab	2025-12-10 17:03:59.513121+00	2025-12-10 17:03:59.513121+00
2d6d9591-937e-4797-97c6-07ebcd1dc0f6	80af13d8-3dcd-41e6-9e1f-6932888266da	1b1156ea-f6d5-43cd-9ce2-ab00d275276d	abcc11c8-855f-4524-8862-4100d24e0bab	2025-12-10 17:03:59.513121+00	2025-12-10 17:03:59.513121+00
383a5556-793b-45fe-ae10-61cb8cf3c091	80af13d8-3dcd-41e6-9e1f-6932888266da	846f2df7-caef-4a9a-adc8-218001827c98	abcc11c8-855f-4524-8862-4100d24e0bab	2025-12-10 17:03:59.513121+00	2025-12-10 17:03:59.513121+00
1e8b8d0d-aaee-4251-be56-67819c8e297b	80af13d8-3dcd-41e6-9e1f-6932888266da	606aeb70-e94c-4b92-9685-b082d8554fdd	abcc11c8-855f-4524-8862-4100d24e0bab	2025-12-10 17:03:59.513121+00	2025-12-10 17:03:59.513121+00
d80d8c99-c71a-4644-baec-e812e171b7ad	80af13d8-3dcd-41e6-9e1f-6932888266da	2f1f1ae5-0f83-4215-aea1-d6ca4846fca8	abcc11c8-855f-4524-8862-4100d24e0bab	2025-12-10 17:03:59.513121+00	2025-12-10 17:03:59.513121+00
e03a61e8-77ec-434d-8d90-2eb4847e98ad	82732d9d-904b-4f60-bc34-dbd6dfd85b97	76440291-a906-49bf-916e-e5330f8e8d67	6d34621f-68f4-42c3-ac00-16793d87a19c	2025-12-10 17:04:34.100945+00	2025-12-10 17:04:34.100945+00
e44e1984-7d8d-4d85-8d7c-a8cce4566e81	82732d9d-904b-4f60-bc34-dbd6dfd85b97	062227e3-a61f-4acf-8799-0afc8423d095	6d34621f-68f4-42c3-ac00-16793d87a19c	2025-12-10 17:04:34.100945+00	2025-12-10 17:04:34.100945+00
1839781c-c52b-4b62-b89f-112c62fce55f	82732d9d-904b-4f60-bc34-dbd6dfd85b97	3b3f78a8-2e0f-4c52-90a3-66ba42fadb1c	6d34621f-68f4-42c3-ac00-16793d87a19c	2025-12-10 17:04:34.100945+00	2025-12-10 17:04:34.100945+00
b3934fe7-8b59-4c90-99f1-e70779b9aacf	82732d9d-904b-4f60-bc34-dbd6dfd85b97	a2a57311-abc8-4f99-96ff-53c140a26019	6d34621f-68f4-42c3-ac00-16793d87a19c	2025-12-10 17:04:34.100945+00	2025-12-10 17:04:34.100945+00
45fdf9ef-7f06-4a3a-8643-18574fa11b33	82732d9d-904b-4f60-bc34-dbd6dfd85b97	1001d4bf-1e79-4da7-8f73-ce94cad191e9	6d34621f-68f4-42c3-ac00-16793d87a19c	2025-12-10 17:04:34.100945+00	2025-12-10 17:04:34.100945+00
9966ae07-b82b-4624-85cd-2f8ea11f4cb5	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	6d418c17-73a8-4eb2-aecf-eef38a23675c	2025-12-10 17:04:34.124754+00	2025-12-10 17:04:34.124754+00
cc51389e-1781-4b27-b3e9-b8257b075067	1bbe551a-fa18-4df7-8897-2d15055d5c28	5f8dc89d-0bc0-4438-8c97-af406ff9a8df	6d418c17-73a8-4eb2-aecf-eef38a23675c	2025-12-10 17:04:34.124754+00	2025-12-10 17:04:34.124754+00
3881dcde-8c6e-4b44-8ed5-531a53a87ae5	1bbe551a-fa18-4df7-8897-2d15055d5c28	5739a7d7-2efb-4572-83d6-0ba02ca5e5f3	6d418c17-73a8-4eb2-aecf-eef38a23675c	2025-12-10 17:04:34.124754+00	2025-12-10 17:04:34.124754+00
849ba9c5-1542-4065-8dd5-30030c5b5f49	1bbe551a-fa18-4df7-8897-2d15055d5c28	4b230f43-4355-44e8-9b21-47e5d0cd055b	6d418c17-73a8-4eb2-aecf-eef38a23675c	2025-12-10 17:04:34.124754+00	2025-12-10 17:04:34.124754+00
39127007-f09f-4a6a-878d-80f233e1c8d0	1bbe551a-fa18-4df7-8897-2d15055d5c28	5685679b-900b-4527-aa76-16a326be111c	6d418c17-73a8-4eb2-aecf-eef38a23675c	2025-12-10 17:04:34.124754+00	2025-12-10 17:04:34.124754+00
004d2f19-98e3-4702-b883-6ba3d47fbb4f	80af13d8-3dcd-41e6-9e1f-6932888266da	1b1156ea-f6d5-43cd-9ce2-ab00d275276d	21befa4d-418c-4ba9-8886-89fd0a44fd4d	2025-12-10 17:04:34.136372+00	2025-12-10 17:04:34.136372+00
a82792d4-fdbc-41f2-a169-4200999d3f8d	80af13d8-3dcd-41e6-9e1f-6932888266da	846f2df7-caef-4a9a-adc8-218001827c98	21befa4d-418c-4ba9-8886-89fd0a44fd4d	2025-12-10 17:04:34.136372+00	2025-12-10 17:04:34.136372+00
70178346-8d9e-4327-a13f-c4fb937661fc	80af13d8-3dcd-41e6-9e1f-6932888266da	606aeb70-e94c-4b92-9685-b082d8554fdd	21befa4d-418c-4ba9-8886-89fd0a44fd4d	2025-12-10 17:04:34.136372+00	2025-12-10 17:04:34.136372+00
3f4bf44b-a1f1-4fcb-9d2a-78634cf57211	80af13d8-3dcd-41e6-9e1f-6932888266da	2f1f1ae5-0f83-4215-aea1-d6ca4846fca8	21befa4d-418c-4ba9-8886-89fd0a44fd4d	2025-12-10 17:04:34.136372+00	2025-12-10 17:04:34.136372+00
89a9ebf0-8314-4e88-9b82-69253b8b92cd	80af13d8-3dcd-41e6-9e1f-6932888266da	f46bc22d-9563-479e-ae43-25eed72a5a13	21befa4d-418c-4ba9-8886-89fd0a44fd4d	2025-12-10 17:04:34.136372+00	2025-12-10 17:04:34.136372+00
8ebf3ae0-f2fe-471e-a15a-fa92c01d6fdd	03ebf868-ea91-44d9-9dda-e328e13d3561	228dee0e-30a5-4f47-b69b-98a1891c3eea	343f8bb5-1274-4581-9f6c-029bf7a2543a	2025-12-10 17:08:55.920191+00	2025-12-10 17:08:55.920191+00
2d40fc49-6c1c-43d3-b675-1e6fe0505913	03ebf868-ea91-44d9-9dda-e328e13d3561	6dd8d52d-0e35-4fbc-9f20-4831d8b8dc56	343f8bb5-1274-4581-9f6c-029bf7a2543a	2025-12-10 17:08:55.920191+00	2025-12-10 17:08:55.920191+00
7bcf6ecf-df0f-44da-ad6c-53ff36abd5b5	03ebf868-ea91-44d9-9dda-e328e13d3561	9870109f-b5ec-4896-90b1-a60b20000c09	343f8bb5-1274-4581-9f6c-029bf7a2543a	2025-12-10 17:08:55.920191+00	2025-12-10 17:08:55.920191+00
09586642-1206-4412-b16d-843b6e23fbd7	03ebf868-ea91-44d9-9dda-e328e13d3561	3c37a771-a3fc-4e48-a653-cad97d644ae8	343f8bb5-1274-4581-9f6c-029bf7a2543a	2025-12-10 17:08:55.920191+00	2025-12-10 17:08:55.920191+00
cb1f0642-4efe-46ed-845e-15a129dcb4a6	03ebf868-ea91-44d9-9dda-e328e13d3561	a6d74d18-9a03-4141-a8bf-80848754bec0	343f8bb5-1274-4581-9f6c-029bf7a2543a	2025-12-10 17:08:55.920191+00	2025-12-10 17:08:55.920191+00
beb5f7c3-ab43-4627-8570-04b971e421bb	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	343f8bb5-1274-4581-9f6c-029bf7a2543a	2025-12-10 17:08:55.920191+00	2025-12-10 17:08:55.920191+00
a980122d-a19c-42bc-9297-9f6aa38a15ec	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b311ef39-43ad-4f53-9883-bdf1f942ace4	28761368-e0bb-474d-ac53-70c57e102f7b	2025-12-10 17:09:06.105368+00	2025-12-10 17:09:06.105368+00
47054f4d-8455-44f9-b9ff-df9ac79f9761	b62ee3ae-1ed9-478b-afb3-9a09473ba774	812d243e-9063-4b61-8616-67904ceeb1fb	28761368-e0bb-474d-ac53-70c57e102f7b	2025-12-10 17:09:06.105368+00	2025-12-10 17:09:06.105368+00
e61dfa21-a923-4972-bfed-9a44dce638be	b62ee3ae-1ed9-478b-afb3-9a09473ba774	8a16c28c-79b3-49ee-8650-f1c702cb7a06	28761368-e0bb-474d-ac53-70c57e102f7b	2025-12-10 17:09:06.105368+00	2025-12-10 17:09:06.105368+00
441c9793-d19c-4c31-9ee4-70eb27082607	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	28761368-e0bb-474d-ac53-70c57e102f7b	2025-12-10 17:09:06.105368+00	2025-12-10 17:09:06.105368+00
e9055588-6cc1-4470-b6da-8d7217b2580a	b62ee3ae-1ed9-478b-afb3-9a09473ba774	3fcb535d-b307-4f13-b04d-28565c934215	28761368-e0bb-474d-ac53-70c57e102f7b	2025-12-10 17:09:06.105368+00	2025-12-10 17:09:06.105368+00
45177ea1-35ce-41e9-bac6-2a4af6a7e3e1	b62ee3ae-1ed9-478b-afb3-9a09473ba774	9850e218-e48e-438d-b9e2-a997af619559	28761368-e0bb-474d-ac53-70c57e102f7b	2025-12-10 17:09:06.105368+00	2025-12-10 17:09:06.105368+00
79e78f2a-d1e5-49b2-8a1c-38f82e395cca	6926a156-9533-45dc-bcb6-b716ab914f46	f2d748f8-44cc-4a61-8cb6-fa2af3bb4b1b	a24c2f9a-a94d-4432-bf2f-dd4fb065a46b	2025-12-10 17:08:55.922494+00	2025-12-10 17:08:55.922494+00
c74c9726-25e6-43e8-b6a0-2c9ff93ffcaf	6926a156-9533-45dc-bcb6-b716ab914f46	7ccbf85d-5fff-454f-974a-32319f6d2d7d	a24c2f9a-a94d-4432-bf2f-dd4fb065a46b	2025-12-10 17:08:55.922494+00	2025-12-10 17:08:55.922494+00
20e95f0e-d4ee-49f4-ade7-95f0e0415129	6926a156-9533-45dc-bcb6-b716ab914f46	353ef5c9-aaa1-404b-98a0-cbb0fa7208cd	a24c2f9a-a94d-4432-bf2f-dd4fb065a46b	2025-12-10 17:08:55.922494+00	2025-12-10 17:08:55.922494+00
9b0231af-ecb2-43f4-aee4-adf432c8526e	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	a24c2f9a-a94d-4432-bf2f-dd4fb065a46b	2025-12-10 17:08:55.922494+00	2025-12-10 17:08:55.922494+00
014181aa-3bfb-4a27-a8f3-7e537211b0bf	6926a156-9533-45dc-bcb6-b716ab914f46	0acc4a3f-ed6b-464b-b6be-4b0038eb0868	a24c2f9a-a94d-4432-bf2f-dd4fb065a46b	2025-12-10 17:08:55.922494+00	2025-12-10 17:08:55.922494+00
c56856de-67ba-4c15-ac92-68006fd585b8	6926a156-9533-45dc-bcb6-b716ab914f46	5b61ccba-92ce-4b63-a213-9bf8e2065217	a24c2f9a-a94d-4432-bf2f-dd4fb065a46b	2025-12-10 17:08:55.922494+00	2025-12-10 17:08:55.922494+00
e5b19aa7-5269-43ff-8efb-3e53bd1f562c	6926a156-9533-45dc-bcb6-b716ab914f46	a3a5c225-c57c-4f06-8995-7ffce5ab5672	d80236e2-7037-4d87-a8e7-d8efb687368d	2025-12-10 17:09:06.106575+00	2025-12-10 17:09:06.106575+00
e07e3a5b-aaeb-42a4-bacb-149e0d6942ce	6926a156-9533-45dc-bcb6-b716ab914f46	7ccbf85d-5fff-454f-974a-32319f6d2d7d	d80236e2-7037-4d87-a8e7-d8efb687368d	2025-12-10 17:09:06.106575+00	2025-12-10 17:09:06.106575+00
02a7a063-4685-4a68-a762-8cbd2df9b3e4	6926a156-9533-45dc-bcb6-b716ab914f46	353ef5c9-aaa1-404b-98a0-cbb0fa7208cd	d80236e2-7037-4d87-a8e7-d8efb687368d	2025-12-10 17:09:06.106575+00	2025-12-10 17:09:06.106575+00
71fe777f-d0ca-4384-af2c-6d4a50dcaa73	6926a156-9533-45dc-bcb6-b716ab914f46	b3aa07c1-7026-4efc-ad63-ebf646491383	d80236e2-7037-4d87-a8e7-d8efb687368d	2025-12-10 17:09:06.106575+00	2025-12-10 17:09:06.106575+00
d8cc348c-c6bf-422b-9ca0-3ccd8a348b11	6926a156-9533-45dc-bcb6-b716ab914f46	0acc4a3f-ed6b-464b-b6be-4b0038eb0868	d80236e2-7037-4d87-a8e7-d8efb687368d	2025-12-10 17:09:06.106575+00	2025-12-10 17:09:06.106575+00
11dd052a-26ac-4719-9257-2cb2b98b6c69	6926a156-9533-45dc-bcb6-b716ab914f46	5b61ccba-92ce-4b63-a213-9bf8e2065217	d80236e2-7037-4d87-a8e7-d8efb687368d	2025-12-10 17:09:06.106575+00	2025-12-10 17:09:06.106575+00
d172f882-6f3a-483e-8730-123e00085a50	b62ee3ae-1ed9-478b-afb3-9a09473ba774	b311ef39-43ad-4f53-9883-bdf1f942ace4	cbc4cf92-2dd2-4c6a-a290-2dabfea12b7c	2025-12-10 17:08:55.924098+00	2025-12-10 17:08:55.924098+00
3d8ab6d5-5453-4f34-8982-296b0165fc76	b62ee3ae-1ed9-478b-afb3-9a09473ba774	812d243e-9063-4b61-8616-67904ceeb1fb	cbc4cf92-2dd2-4c6a-a290-2dabfea12b7c	2025-12-10 17:08:55.924098+00	2025-12-10 17:08:55.924098+00
219dbbc3-6515-4f9d-9945-3978804d097e	b62ee3ae-1ed9-478b-afb3-9a09473ba774	60fdb01d-3d08-4d79-81d2-d069c9a711ec	cbc4cf92-2dd2-4c6a-a290-2dabfea12b7c	2025-12-10 17:08:55.924098+00	2025-12-10 17:08:55.924098+00
1f443e5d-86cd-4221-b4a9-996dc595ac23	b62ee3ae-1ed9-478b-afb3-9a09473ba774	bd243c4e-d927-438b-a355-9f93290bdebc	cbc4cf92-2dd2-4c6a-a290-2dabfea12b7c	2025-12-10 17:08:55.924098+00	2025-12-10 17:08:55.924098+00
9518621a-6ccc-4f2f-9002-581fbbb6609e	b62ee3ae-1ed9-478b-afb3-9a09473ba774	3fcb535d-b307-4f13-b04d-28565c934215	cbc4cf92-2dd2-4c6a-a290-2dabfea12b7c	2025-12-10 17:08:55.924098+00	2025-12-10 17:08:55.924098+00
144dce25-a653-46bf-a674-cfa7ef1860ad	b62ee3ae-1ed9-478b-afb3-9a09473ba774	9850e218-e48e-438d-b9e2-a997af619559	cbc4cf92-2dd2-4c6a-a290-2dabfea12b7c	2025-12-10 17:08:55.924098+00	2025-12-10 17:08:55.924098+00
d56d17a2-9bde-431c-9b80-e8fdd5a19116	03ebf868-ea91-44d9-9dda-e328e13d3561	228dee0e-30a5-4f47-b69b-98a1891c3eea	93a7c0c3-0fc5-4824-942f-efcb02afb100	2025-12-10 17:09:06.125246+00	2025-12-10 17:09:06.125246+00
a3700077-4b2f-4ce5-b32a-fe1d49b995e5	03ebf868-ea91-44d9-9dda-e328e13d3561	6dd8d52d-0e35-4fbc-9f20-4831d8b8dc56	93a7c0c3-0fc5-4824-942f-efcb02afb100	2025-12-10 17:09:06.125246+00	2025-12-10 17:09:06.125246+00
96969d23-01e5-45ad-8c7e-5bf69b9e9a97	03ebf868-ea91-44d9-9dda-e328e13d3561	9870109f-b5ec-4896-90b1-a60b20000c09	93a7c0c3-0fc5-4824-942f-efcb02afb100	2025-12-10 17:09:06.125246+00	2025-12-10 17:09:06.125246+00
cca46c0a-2d34-4fdb-b44e-f24a3faab6f0	03ebf868-ea91-44d9-9dda-e328e13d3561	3c37a771-a3fc-4e48-a653-cad97d644ae8	93a7c0c3-0fc5-4824-942f-efcb02afb100	2025-12-10 17:09:06.125246+00	2025-12-10 17:09:06.125246+00
5782cec0-c79e-4593-95e2-cfa471915dbb	03ebf868-ea91-44d9-9dda-e328e13d3561	21a8c294-572f-4db7-9333-7514acb78a92	93a7c0c3-0fc5-4824-942f-efcb02afb100	2025-12-10 17:09:06.125246+00	2025-12-10 17:09:06.125246+00
097330d7-bcbf-4bb4-a108-5973b6646da9	03ebf868-ea91-44d9-9dda-e328e13d3561	508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	93a7c0c3-0fc5-4824-942f-efcb02afb100	2025-12-10 17:09:06.125246+00	2025-12-10 17:09:06.125246+00
54b5a1f4-a920-48f0-82a4-b8b37e528853	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	922132d3-9ca5-4554-be9d-3ca066fe9f15	2025-12-10 17:27:22.376551+00	2025-12-10 17:27:22.376551+00
38e2a8d2-a5e3-4489-a836-b759a4b22a6c	1bbe551a-fa18-4df7-8897-2d15055d5c28	5739a7d7-2efb-4572-83d6-0ba02ca5e5f3	922132d3-9ca5-4554-be9d-3ca066fe9f15	2025-12-10 17:27:22.376551+00	2025-12-10 17:27:22.376551+00
f5c7cb0a-d686-444a-b225-4081b89ff9f0	1bbe551a-fa18-4df7-8897-2d15055d5c28	4b230f43-4355-44e8-9b21-47e5d0cd055b	922132d3-9ca5-4554-be9d-3ca066fe9f15	2025-12-10 17:27:22.376551+00	2025-12-10 17:27:22.376551+00
befe663c-89db-410a-8f51-f514d1343a4b	1bbe551a-fa18-4df7-8897-2d15055d5c28	5685679b-900b-4527-aa76-16a326be111c	922132d3-9ca5-4554-be9d-3ca066fe9f15	2025-12-10 17:27:22.376551+00	2025-12-10 17:27:22.376551+00
a5aacbe8-5303-4aba-ba32-1a86672c0a1b	1bbe551a-fa18-4df7-8897-2d15055d5c28	4c9f189b-a492-4249-a1e7-0f1a8c1d9eaf	922132d3-9ca5-4554-be9d-3ca066fe9f15	2025-12-10 17:27:22.376551+00	2025-12-10 17:27:22.376551+00
1ad0b3e8-e574-467f-a41c-e94e6e98120a	1bbe551a-fa18-4df7-8897-2d15055d5c28	62b816aa-e8cc-4a94-9679-40dc3d7872ea	638ee532-62bc-454a-ba1e-be5144df49fe	2025-12-10 17:27:23.823631+00	2025-12-10 17:27:23.823631+00
393bc7f6-bfd8-4377-a5b1-d284c34cab6d	1bbe551a-fa18-4df7-8897-2d15055d5c28	5739a7d7-2efb-4572-83d6-0ba02ca5e5f3	638ee532-62bc-454a-ba1e-be5144df49fe	2025-12-10 17:27:23.823631+00	2025-12-10 17:27:23.823631+00
862e33a7-f066-4aa8-a1ac-36fc6d212d51	1bbe551a-fa18-4df7-8897-2d15055d5c28	5685679b-900b-4527-aa76-16a326be111c	638ee532-62bc-454a-ba1e-be5144df49fe	2025-12-10 17:27:23.823631+00	2025-12-10 17:27:23.823631+00
2970e230-70d6-48d3-a159-8255737b089e	1bbe551a-fa18-4df7-8897-2d15055d5c28	4c9f189b-a492-4249-a1e7-0f1a8c1d9eaf	638ee532-62bc-454a-ba1e-be5144df49fe	2025-12-10 17:27:23.823631+00	2025-12-10 17:27:23.823631+00
5377d679-02fb-4387-896c-877bac75218e	1bbe551a-fa18-4df7-8897-2d15055d5c28	853c23fc-1570-4915-be51-7036c4fa7900	638ee532-62bc-454a-ba1e-be5144df49fe	2025-12-10 17:27:23.823631+00	2025-12-10 17:27:23.823631+00
7debfdea-aa07-4fd6-943a-e2035d014d63	7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	89a88a0a-83f4-45ad-82a5-b18bb485d923	0b63fb2a-98cc-43f6-842e-4b175897c1a1	2025-12-16 21:19:27.779776+00	2025-12-16 21:19:27.779776+00
b4c330f1-2204-4cd1-89ca-c2528b43c426	a8048ec8-1200-453e-b7cb-4a0dedb9eb89	d708872d-4388-413b-8d26-34dec7c03330	61716c00-afa9-439d-a2b7-dde4323178b3	2025-12-16 21:19:27.787693+00	2025-12-16 21:19:27.787693+00
8b1861d8-aa3e-48c9-87a8-84cb65fa1ad2	aaf3c10b-93ec-44cb-9211-cbfc97c13ff3	0cc0b055-a162-4db6-87d6-fbf33cf8a582	02a2df79-2e79-4d7a-82e4-858c0e2e8791	2025-12-16 21:19:27.787196+00	2025-12-16 21:19:27.787196+00
0d5dde8d-7c75-4e36-ba93-b87dc84ac5d7	a8048ec8-1200-453e-b7cb-4a0dedb9eb89	b6ef26e2-6a25-45b8-8e76-04ca9bafce82	193445f8-f1be-48e8-8977-dff7dc7d7500	2025-12-16 21:19:57.902452+00	2025-12-16 21:19:57.902452+00
e9ae251c-a317-4376-816f-47d8ee6c79f4	aaf3c10b-93ec-44cb-9211-cbfc97c13ff3	d086629c-cfe2-483e-9eac-6c7e85e6fc0f	04934493-fc86-4180-a43f-d433eb0c7b71	2025-12-16 21:19:57.925477+00	2025-12-16 21:19:57.925477+00
7a0f8549-8634-4dfa-8a57-04d72f42491a	7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	ccb8518e-92b7-467f-8800-4fd0947ccf12	64031704-c907-4f2e-b837-e05a6e92b1c5	2025-12-16 21:19:57.926056+00	2025-12-16 21:19:57.926056+00
e4f9f1cd-f736-4ab3-ae4a-383b64f94d8a	7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	e57d2714-4847-43a5-b278-7105a36920d6	9f099675-063e-4ef9-8b94-c5e04edeaca9	2025-12-16 21:29:01.65417+00	2025-12-16 21:29:01.65417+00
\.


--
-- Data for Name: secret_snapshots; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_snapshots (id, "envId", "folderId", "parentFolderId", "createdAt", "updatedAt") FROM stdin;
a33b7588-920a-4d76-85d1-2212953a84ad	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:38:23.477548+00	2025-10-22 15:38:23.477548+00
26850928-66f3-40bc-9fe7-c64434257208	31fcb5e1-23f2-4589-b779-167352214b1f	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:38:58.218459+00	2025-10-22 15:38:58.218459+00
e7cd9f89-63b0-43da-ab0c-7dbf4bad0855	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:39:15.77807+00	2025-10-22 15:39:15.77807+00
96bc2150-fe95-43e6-a478-597a7d9ae057	31fcb5e1-23f2-4589-b779-167352214b1f	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:40:04.880756+00	2025-10-22 15:40:04.880756+00
908a703e-e447-420b-8e65-32a55447cb75	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:40:04.897563+00	2025-10-22 15:40:04.897563+00
ec01c098-acb2-42af-8cfe-e10b3c1a1ad8	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:40:04.921829+00	2025-10-22 15:40:04.921829+00
58504cbe-7c66-4529-83a8-bc7249cd3fc2	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:40:08.286669+00	2025-10-22 15:40:08.286669+00
b8313e4b-fe31-44dd-adb3-cb7403d5c315	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:40:08.289294+00	2025-10-22 15:40:08.289294+00
0271b03c-30d8-4968-a603-3396991f3a95	31fcb5e1-23f2-4589-b779-167352214b1f	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:40:08.292139+00	2025-10-22 15:40:08.292139+00
e16f2e91-2a43-4ecf-8dda-490831c9a16c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	18bb9dff-2f16-40d3-93e6-6d8e606f9a77	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:40:36.646511+00	2025-10-22 15:40:36.646511+00
e5544f2e-62b2-477f-9efb-b8da6cab6725	31fcb5e1-23f2-4589-b779-167352214b1f	8fd3572b-38d8-4e8c-9d2f-98257fed9729	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:40:36.643723+00	2025-10-22 15:40:36.643723+00
a020aaca-d36c-4b56-8543-53930406a194	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	580bbcd8-2935-468a-a6fa-9ad9d3398fe3	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:40:36.653355+00	2025-10-22 15:40:36.653355+00
08f8c54e-8875-4d54-9c6b-13b283c6d319	a28ceab1-d6a2-404e-b21b-fb9a14194e65	18bb9dff-2f16-40d3-93e6-6d8e606f9a77	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:40:39.886779+00	2025-10-22 15:40:39.886779+00
065e3bbb-15f4-40e8-92c8-bd52b002b0d3	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	580bbcd8-2935-468a-a6fa-9ad9d3398fe3	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:40:39.902174+00	2025-10-22 15:40:39.902174+00
37687120-1af6-4650-bd57-012b764ad5d5	31fcb5e1-23f2-4589-b779-167352214b1f	8fd3572b-38d8-4e8c-9d2f-98257fed9729	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:40:39.943691+00	2025-10-22 15:40:39.943691+00
d23cd8ec-953d-4648-9540-ae8ef754c16a	a28ceab1-d6a2-404e-b21b-fb9a14194e65	18bb9dff-2f16-40d3-93e6-6d8e606f9a77	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:40:43.73544+00	2025-10-22 15:40:43.73544+00
d21a4aac-7263-442f-ace2-57613eeaf24d	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	580bbcd8-2935-468a-a6fa-9ad9d3398fe3	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:40:43.737499+00	2025-10-22 15:40:43.737499+00
6b5ff9b5-2d9b-4f11-8f51-fed86c8abd7a	31fcb5e1-23f2-4589-b779-167352214b1f	8fd3572b-38d8-4e8c-9d2f-98257fed9729	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:40:43.733919+00	2025-10-22 15:40:43.733919+00
f8ce7a58-e59c-4a65-9d32-3b382eb56ba3	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:42:26.158735+00	2025-10-22 15:42:26.158735+00
b28e3151-c34f-48c5-9ebc-57f95c0f2050	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:42:56.362656+00	2025-10-22 15:42:56.362656+00
6a06f20a-e51a-46cc-9158-48dc16b22d6c	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:48:26.606235+00	2025-10-22 15:48:26.606235+00
9420dac8-bf23-4133-b428-9b10ea98d095	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:48:27.02419+00	2025-10-22 15:48:27.02419+00
57ef27db-a4f8-4c7f-9111-1f448c46b6e8	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:48:35.032273+00	2025-10-22 15:48:35.032273+00
f2cd2594-1b55-4de4-ae32-5d8ab030f4a4	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:48:35.557049+00	2025-10-22 15:48:35.557049+00
1cdecf28-bf7b-4400-8a9d-40e187210988	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:48:43.226385+00	2025-10-22 15:48:43.226385+00
0a5ff89c-5e31-490c-a77e-2bdad892d003	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:48:43.580855+00	2025-10-22 15:48:43.580855+00
5952dc35-c15f-4132-ba89-9bfeb6652328	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:48:51.234639+00	2025-10-22 15:48:51.234639+00
efb07b17-4fc8-44c9-afb2-5b5a889696ee	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:48:51.629027+00	2025-10-22 15:48:51.629027+00
823131c6-8946-4de6-a3b1-699f43f4e4e1	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:49:02.397456+00	2025-10-22 15:49:02.397456+00
d40bd981-9966-461b-b146-91678b54bec1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:49:02.771452+00	2025-10-22 15:49:02.771452+00
fd0ff6cb-e0e7-4404-9b36-19bfa11c9ca8	31fcb5e1-23f2-4589-b779-167352214b1f	e1ae276b-68ce-4c00-89e8-5b4a1734760b	8fd3572b-38d8-4e8c-9d2f-98257fed9729	2025-10-22 15:50:13.320327+00	2025-10-22 15:50:13.320327+00
c54d1694-6719-44bc-b95c-a29940ef0a60	a28ceab1-d6a2-404e-b21b-fb9a14194e65	a8e47cea-2024-4f7c-b1e0-fa69de68f888	18bb9dff-2f16-40d3-93e6-6d8e606f9a77	2025-10-22 15:50:13.332932+00	2025-10-22 15:50:13.332932+00
a4f5efcd-0746-4e2f-bee4-89ee46c82629	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	d1d47cac-650b-438e-bee0-db8446b7a111	580bbcd8-2935-468a-a6fa-9ad9d3398fe3	2025-10-22 15:50:13.335666+00	2025-10-22 15:50:13.335666+00
f6beecf7-815d-4597-a7bf-8ca9fdefaae9	31fcb5e1-23f2-4589-b779-167352214b1f	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:50:28.096783+00	2025-10-22 15:50:28.096783+00
31796b85-aa5b-44c3-af7d-682a0f3cf177	a28ceab1-d6a2-404e-b21b-fb9a14194e65	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:50:28.199861+00	2025-10-22 15:50:28.199861+00
4d2d9e81-38ec-448b-9adc-ab137ae8440a	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:50:28.230784+00	2025-10-22 15:50:28.230784+00
3b6ac231-5108-4c85-9a1f-aa8ca5800a68	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 19:08:40.3366+00	2025-10-22 19:08:40.3366+00
ce89aa13-825e-42e1-ac6a-48da442c4706	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 19:08:40.388951+00	2025-10-22 19:08:40.388951+00
c9eee93c-88cc-40d3-a31a-dd53b4575c69	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 19:08:40.392052+00	2025-10-22 19:08:40.392052+00
c8a1d50b-e27d-4d1d-b1fd-fc10f6d32101	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-10-22 19:08:40.635049+00	2025-10-22 19:08:40.635049+00
eb5fe9ef-f761-462f-9da5-fa8107b7d62c	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-23 17:35:42.485666+00	2025-10-23 17:35:42.485666+00
70c0f88c-e064-4800-85f5-cf33bbe1a3f7	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-23 17:35:57.182788+00	2025-10-23 17:35:57.182788+00
ff1a57c6-d8e8-4da6-b7ed-b31462732821	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-10-23 17:36:09.331296+00	2025-10-23 17:36:09.331296+00
0d1125b1-012b-4d6f-8484-46996dd555b9	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-10-23 17:36:18.805379+00	2025-10-23 17:36:18.805379+00
34e575ff-4cee-4d18-8cb9-c732c9461a6d	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-10-22 19:09:36.177485+00	2025-10-22 19:09:36.177485+00
619062dc-ca8c-4ec2-a3ec-5e8c64b8ddb9	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-10-22 19:09:36.860664+00	2025-10-22 19:09:36.860664+00
7a509fd6-9a5e-46c3-90cd-e2eba74c3e99	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-23 17:35:42.487945+00	2025-10-23 17:35:42.487945+00
8ae86467-0613-4c2e-ab6f-61f177db297b	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-23 17:35:42.571562+00	2025-10-23 17:35:42.571562+00
c56b1432-7397-4973-a5f9-1301b14a0801	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-10-23 17:35:42.683977+00	2025-10-23 17:35:42.683977+00
a08baf2e-5b44-4033-bab5-249171a8b649	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-10-23 17:35:42.732548+00	2025-10-23 17:35:42.732548+00
0924bede-d2bf-4767-b728-fc9017264a7d	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-10-23 17:35:42.771572+00	2025-10-23 17:35:42.771572+00
e9b37274-3573-46ed-bccb-dc3013a92ed5	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-23 17:35:57.188359+00	2025-10-23 17:35:57.188359+00
9d7918df-d87b-4ce3-a987-205b8a955824	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-23 17:35:57.200077+00	2025-10-23 17:35:57.200077+00
f7890219-4be3-4a85-bbc9-43c918d021b1	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-10-23 17:35:57.317269+00	2025-10-23 17:35:57.317269+00
8f3594c8-3884-4d3e-a46e-c813edb9797f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-10-23 17:35:57.451681+00	2025-10-23 17:35:57.451681+00
dd3514f7-f33d-45a1-b346-ee2cb0ed4c77	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-10-23 17:35:57.474109+00	2025-10-23 17:35:57.474109+00
f6e6454d-0700-4c79-aae1-c782411d0ce3	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-10-23 17:36:09.353731+00	2025-10-23 17:36:09.353731+00
4442fe37-6949-4e6b-b303-dded9ebc5b0b	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-10-23 17:36:09.383099+00	2025-10-23 17:36:09.383099+00
e6ced538-0c2b-4982-b7d9-fb19b80b00c4	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-10-23 17:36:18.800541+00	2025-10-23 17:36:18.800541+00
cde60cd3-bf0a-4a83-9e07-89c1a932d82f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-10-23 17:36:18.816615+00	2025-10-23 17:36:18.816615+00
b814cc7e-c3d1-4329-ab1a-67bf12589894	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-10-23 17:36:29.922389+00	2025-10-23 17:36:29.922389+00
1b460ba5-b6ed-44ef-b275-eb41c85ade8f	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-10-23 17:36:30.959946+00	2025-10-23 17:36:30.959946+00
c4f531da-19c4-48cc-b22b-86617413672a	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-10-23 17:36:42.666443+00	2025-10-23 17:36:42.666443+00
ecd69e76-4439-4179-bd5f-ac447fe85ebe	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-10-23 17:36:47.951595+00	2025-10-23 17:36:47.951595+00
bbc98866-27c3-418c-b354-f669c4a59f33	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-10-23 17:37:18.779615+00	2025-10-23 17:37:18.779615+00
4cbe15d1-3b20-4374-a2ef-09daf084a68f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-10-23 17:37:19.436745+00	2025-10-23 17:37:19.436745+00
06eb20dc-be63-4ba5-ae8e-c4547fe3f2e9	5eb8c92e-5aeb-4aa6-8615-13e8a3163a40	e4511410-f276-46e6-82bf-074363964703	\N	2025-11-11 19:17:13.570561+00	2025-11-11 19:17:13.570561+00
69e761be-2d5d-4bd0-abb9-96cf3783fbb0	24f31f48-cb28-4bb5-b231-8917e97559e6	05c2e293-0bfe-4acc-81cb-0b04ee0a5566	\N	2025-11-11 19:17:13.575587+00	2025-11-11 19:17:13.575587+00
0c0ae51e-5c02-421e-9a49-2dc8b0a22901	15a1dd97-f1d2-455f-8328-141644e1f032	8ae0e6fa-1c96-4b4e-a9c3-9f64c63f6ebe	\N	2025-11-11 19:17:13.57747+00	2025-11-11 19:17:13.57747+00
05963048-42aa-45ad-8413-37b5427f9a4c	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-11-13 19:48:58.130416+00	2025-11-13 19:48:58.130416+00
0ea4a46a-ce0f-4f01-8af1-02de0ddcc0c5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-11-13 19:48:58.157749+00	2025-11-13 19:48:58.157749+00
ac175104-e7cd-44c6-a18b-be800f1f1b3f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-11-13 19:48:58.165122+00	2025-11-13 19:48:58.165122+00
37f71a2a-ce5b-42d1-973f-144aac126ca7	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-11-13 19:48:58.262545+00	2025-11-13 19:48:58.262545+00
6b360892-ab5f-4616-9f5a-f8631870e62f	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-11-13 19:48:58.347245+00	2025-11-13 19:48:58.347245+00
dbce13cd-e5ba-412c-b5b3-c2e78f5eb893	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-11-13 19:48:58.444821+00	2025-11-13 19:48:58.444821+00
76e98719-8de2-44ad-bde6-c8757dd9b2f4	31fcb5e1-23f2-4589-b779-167352214b1f	ffc0c4c3-5350-44ea-a573-0f99a532677f	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-11-13 19:49:18.788304+00	2025-11-13 19:49:18.788304+00
458986f7-3a58-4cf0-aea8-fc49e5685343	a28ceab1-d6a2-404e-b21b-fb9a14194e65	bea88e16-53a2-478c-b653-4cf2349caf7d	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-11-13 19:49:18.816499+00	2025-11-13 19:49:18.816499+00
4fed09b4-e4b6-4125-82b3-ae8d70d764fd	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	43cf1568-8fc2-4401-819c-e62949351c07	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-11-13 19:49:18.823565+00	2025-11-13 19:49:18.823565+00
fe91c0e4-2a48-48ab-8add-7b04733dcca6	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-11-13 19:49:18.860127+00	2025-11-13 19:49:18.860127+00
2d583463-e828-4f3f-8cee-84c597b1a7e2	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-11-13 19:49:18.906601+00	2025-11-13 19:49:18.906601+00
9881e1c3-3ebd-4e04-aea7-77db98a5c764	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-11-13 19:49:18.908141+00	2025-11-13 19:49:18.908141+00
20baf6d9-d7e7-4f31-82d0-cd60e0348cda	31fcb5e1-23f2-4589-b779-167352214b1f	04c8a5bb-668a-4207-a189-3549854ddfce	ffc0c4c3-5350-44ea-a573-0f99a532677f	2025-11-13 19:53:54.315386+00	2025-11-13 19:53:54.315386+00
7af1d203-b0b5-45a6-bc16-5da8ccb3a807	6b264ab4-f82b-4f0b-b39c-741aeeb507e4	5bc6e6bb-7529-4395-abdf-bd66d0adb699	43cf1568-8fc2-4401-819c-e62949351c07	2025-11-13 19:53:54.359911+00	2025-11-13 19:53:54.359911+00
3bdae9f7-1a81-467d-8eaa-f1061d1199f5	a28ceab1-d6a2-404e-b21b-fb9a14194e65	2707578f-df91-451e-80b7-f2fc488e815a	bea88e16-53a2-478c-b653-4cf2349caf7d	2025-11-13 19:53:54.36309+00	2025-11-13 19:53:54.36309+00
2e58fb3d-0641-434a-9250-55404ed268e8	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:14:17.079003+00	2025-12-08 18:14:17.079003+00
309cc460-870c-4f46-a031-edd41d05b9a0	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:14:21.85834+00	2025-12-08 18:14:21.85834+00
6e355de3-2069-464e-9791-fa6b22d63537	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:14:25.323718+00	2025-12-08 18:14:25.323718+00
249e7b77-4ca0-4d94-9e3a-1a97d07e72ff	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:39:54.464437+00	2025-12-08 18:39:54.464437+00
e70062f1-a42c-4e05-a06d-be69f02b4726	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:39:54.48761+00	2025-12-08 18:39:54.48761+00
aa8af915-85be-40cd-b55b-104c032c7240	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:39:54.492089+00	2025-12-08 18:39:54.492089+00
de893e4f-1bc9-4727-ae1f-3aea4c08b564	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:41:13.384341+00	2025-12-08 18:41:13.384341+00
502ee93a-8303-46c7-9eec-5e6a777c83e9	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:41:13.427666+00	2025-12-08 18:41:13.427666+00
e288278f-f024-4392-ad2c-c38cfe99ce87	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:41:13.446342+00	2025-12-08 18:41:13.446342+00
6b0008c3-22e4-4e74-a974-f7801a22129d	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:41:28.164456+00	2025-12-08 18:41:28.164456+00
86289a94-9156-475b-8d44-b1bf031858d4	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:41:28.184281+00	2025-12-08 18:41:28.184281+00
b3557670-8efd-4bdf-983c-57813c3bf7c3	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:41:28.185539+00	2025-12-08 18:41:28.185539+00
cf6c7f1e-413d-4555-ab5e-9cd6d4e568ce	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:41:55.528558+00	2025-12-08 18:41:55.528558+00
50eb73b2-0e38-4b2e-8231-037a18291d34	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:41:55.834764+00	2025-12-08 18:41:55.834764+00
d90a5199-e375-4c6b-b672-a43204d0c37a	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:41:56.185757+00	2025-12-08 18:41:56.185757+00
fdd66c3c-f5dc-4a02-a95c-544b3f2e7a9a	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:42:07.092213+00	2025-12-08 18:42:07.092213+00
d543c567-aa5f-4d1d-adc3-d8d546c8131f	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:42:07.110935+00	2025-12-08 18:42:07.110935+00
9c7f46c2-a93f-44db-94bc-b37940df2960	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:42:07.11454+00	2025-12-08 18:42:07.11454+00
36ce7d77-9b3b-4839-a7a5-045f1eb56426	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:16.966478+00	2025-12-08 19:08:16.966478+00
cdf6bda8-0e29-4af5-9844-0789dc399868	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:16.993941+00	2025-12-08 19:08:16.993941+00
72e0e25e-ec7c-4e2a-980b-daa0fa30b4a2	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:17.018353+00	2025-12-08 19:08:17.018353+00
29ae677c-d49c-4c57-8ac4-3c84522cf6a5	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:25.233666+00	2025-12-08 19:08:25.233666+00
108a71a1-162e-417c-be7c-95e466cd6aae	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:25.244484+00	2025-12-08 19:08:25.244484+00
fabf95ec-df86-43ab-89c2-1f1a28da028a	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:25.248671+00	2025-12-08 19:08:25.248671+00
01bb5600-6b0b-4a02-aefb-4ca674fb0b01	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:31.709611+00	2025-12-08 19:08:31.709611+00
658c7443-60ad-4b3f-88a5-54dd3f96d7c5	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:31.758304+00	2025-12-08 19:08:31.758304+00
bd0f06e8-fafd-4425-bc9e-0529cae863a0	2a4b77b6-37a2-484c-b5e7-79cd9f6d0983	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:41.609181+00	2025-12-08 19:08:41.609181+00
7c777bcf-fbfa-4668-b7bc-cab04e2b7988	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:41.639564+00	2025-12-08 19:08:41.639564+00
437a735c-6fd6-4690-a99e-f9c60a84f8ad	3e8a705e-9742-43ea-96cb-89fe88aed058	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:31.755334+00	2025-12-08 19:08:31.755334+00
eaa7e540-3890-41ac-861f-66c4771b4adc	ef1eb14f-77c9-48ae-85df-00bd73ca4a85	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:41.636896+00	2025-12-08 19:08:41.636896+00
cd7b30cd-27a2-4041-b9a1-38e93e9314c1	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:48:15.125983+00	2025-12-10 16:48:15.125983+00
e9622930-b80d-402b-8bd1-0e5928c466a5	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:48:15.145414+00	2025-12-10 16:48:15.145414+00
fbf45c00-0679-4801-9481-1aa332fce815	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:48:41.89302+00	2025-12-10 16:48:41.89302+00
f654f316-8ac5-4679-8d05-747c5a4148f1	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:48:41.897174+00	2025-12-10 16:48:41.897174+00
c400b21c-4b83-414c-9d74-9fa7732068fe	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:48:51.24781+00	2025-12-10 16:48:51.24781+00
1951752b-063a-4f70-ae27-7af64d5e758d	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:48:51.25144+00	2025-12-10 16:48:51.25144+00
28727c55-fa95-4cd3-90c9-3f0ad1733202	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:48:51.253088+00	2025-12-10 16:48:51.253088+00
6402a1ce-5cc8-42e0-a3f2-20b33440d76d	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:49:03.479122+00	2025-12-10 16:49:03.479122+00
b103586f-6355-4fa2-85d2-36725965b745	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:03.480265+00	2025-12-10 16:49:03.480265+00
e2884f3d-cadc-4b44-993c-ddf1d85bf58d	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:49:03.487099+00	2025-12-10 16:49:03.487099+00
614677d4-8d12-4992-8ad6-7e0d89bc1a93	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:49:13.07186+00	2025-12-10 16:49:13.07186+00
23cd7e73-8fdb-4865-9e25-3c6435929e76	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:49:13.521552+00	2025-12-10 16:49:13.521552+00
884ace89-391c-40ee-bebe-1badab2e7e42	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:13.99375+00	2025-12-10 16:49:13.99375+00
731c1cdd-3a88-4ed0-b23e-8d053cc9ec53	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:28.668133+00	2025-12-10 16:49:28.668133+00
287c3542-bada-4229-84d9-e8d0cadd1e67	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:49:45.216132+00	2025-12-10 16:49:45.216132+00
84ed8146-c94b-4ec6-93e6-cbf7915b9d52	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:49:45.972407+00	2025-12-10 16:49:45.972407+00
376eec01-7036-45eb-ae37-8353aa9a318e	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:46.697773+00	2025-12-10 16:49:46.697773+00
db7bc43b-a3a6-4add-9f4a-7d19d5cfa7ee	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:50:02.170782+00	2025-12-10 16:50:02.170782+00
05a00379-5cc7-4d9f-a7c5-ebf35c641322	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:50:12.839074+00	2025-12-10 16:50:12.839074+00
ccc8318f-ba0e-410b-8a5a-d395969216fa	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:50:13.321085+00	2025-12-10 16:50:13.321085+00
752bcdcb-a9b5-4d9c-8d99-06b486c1a7ea	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:50:36.983041+00	2025-12-10 16:50:36.983041+00
f3f3cbaf-d2ed-47a6-b4f8-425a354cd07f	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:22.533923+00	2025-12-10 16:52:22.533923+00
5827906c-1712-416e-8028-29c877e5c58c	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:28.820169+00	2025-12-10 16:52:28.820169+00
ac23d5e9-e3f0-4629-8c4f-65ad6f8a20f7	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:28.841782+00	2025-12-10 16:52:28.841782+00
a6f82c7c-8f39-4187-a2e3-31b9e34bc778	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:28.844098+00	2025-12-10 16:52:28.844098+00
ad90c18c-e444-4a8f-897a-6eafb96306a3	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:37.676376+00	2025-12-10 16:52:37.676376+00
798b2ba7-c56d-4692-8863-6c7ed546314b	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:37.710904+00	2025-12-10 16:52:37.710904+00
0dcc1b5a-1183-47dc-ae8c-79fa4bbe105e	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:37.715147+00	2025-12-10 16:52:37.715147+00
e06c97a1-d03f-42d8-a150-b3e92ce957c9	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:57.349473+00	2025-12-10 16:52:57.349473+00
912e0433-5fa7-41b9-b033-f41af15e5021	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:58.040105+00	2025-12-10 16:52:58.040105+00
4830be76-5d56-471f-a0b7-48b9e0317378	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:53:10.401875+00	2025-12-10 16:53:10.401875+00
d899ca8c-824f-4346-a08b-f3127a3b2732	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:53:11.174062+00	2025-12-10 16:53:11.174062+00
a0cac501-ec7b-4a6e-8895-72b4b95d49f8	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:53:11.619565+00	2025-12-10 16:53:11.619565+00
535e0eac-e48c-4955-aafd-08e1dafb0cf5	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:53:26.42627+00	2025-12-10 16:53:26.42627+00
51390b37-1c56-449b-ab7b-915887ff17b8	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:53:27.088316+00	2025-12-10 16:53:27.088316+00
1dfe70fa-5610-4586-848a-2e24fa93fcf1	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:53:54.395218+00	2025-12-10 16:53:54.395218+00
0ff35def-bea0-4650-b381-7e08a9c6a894	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:53:54.898697+00	2025-12-10 16:53:54.898697+00
88301ebf-b8d5-4ca6-88c0-6adb5af10a43	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:53:55.316768+00	2025-12-10 16:53:55.316768+00
3dea9793-cf58-4f7b-9b6a-8430235d24cb	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:54:09.627037+00	2025-12-10 16:54:09.627037+00
89211f2f-1a7e-4ee6-b81c-2ed7af5e6f09	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:54:10.137534+00	2025-12-10 16:54:10.137534+00
323166e4-0fb0-4979-a69e-b60e56cb84dd	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:54:10.595654+00	2025-12-10 16:54:10.595654+00
c8f2930f-d8a1-40e8-a01d-f8eb4a72ddac	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:54:23.432763+00	2025-12-10 16:54:23.432763+00
0b1195b2-2af2-497f-8390-777c46d938ea	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:54:24.093831+00	2025-12-10 16:54:24.093831+00
7d4f967d-0c36-405d-93ce-f66c828ed81d	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:54:26.229685+00	2025-12-10 16:54:26.229685+00
28deac9b-9120-47ba-b5a3-d843104c3664	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 17:03:42.161447+00	2025-12-10 17:03:42.161447+00
de1e1f92-9460-451e-bd00-1f146233dbe5	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 17:03:47.580452+00	2025-12-10 17:03:47.580452+00
7858091a-9b9e-4eaf-babf-d4912ed27475	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 17:03:48.260476+00	2025-12-10 17:03:48.260476+00
fffe9ee2-7f55-43c7-888e-0aaf83d46984	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 17:03:58.899477+00	2025-12-10 17:03:58.899477+00
abcc11c8-855f-4524-8862-4100d24e0bab	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 17:03:59.513121+00	2025-12-10 17:03:59.513121+00
6d34621f-68f4-42c3-ac00-16793d87a19c	82732d9d-904b-4f60-bc34-dbd6dfd85b97	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 17:04:34.100945+00	2025-12-10 17:04:34.100945+00
6d418c17-73a8-4eb2-aecf-eef38a23675c	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 17:04:34.124754+00	2025-12-10 17:04:34.124754+00
21befa4d-418c-4ba9-8886-89fd0a44fd4d	80af13d8-3dcd-41e6-9e1f-6932888266da	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 17:04:34.136372+00	2025-12-10 17:04:34.136372+00
343f8bb5-1274-4581-9f6c-029bf7a2543a	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 17:08:55.920191+00	2025-12-10 17:08:55.920191+00
a24c2f9a-a94d-4432-bf2f-dd4fb065a46b	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 17:08:55.922494+00	2025-12-10 17:08:55.922494+00
cbc4cf92-2dd2-4c6a-a290-2dabfea12b7c	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 17:08:55.924098+00	2025-12-10 17:08:55.924098+00
28761368-e0bb-474d-ac53-70c57e102f7b	b62ee3ae-1ed9-478b-afb3-9a09473ba774	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 17:09:06.105368+00	2025-12-10 17:09:06.105368+00
d80236e2-7037-4d87-a8e7-d8efb687368d	6926a156-9533-45dc-bcb6-b716ab914f46	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 17:09:06.106575+00	2025-12-10 17:09:06.106575+00
93a7c0c3-0fc5-4824-942f-efcb02afb100	03ebf868-ea91-44d9-9dda-e328e13d3561	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 17:09:06.125246+00	2025-12-10 17:09:06.125246+00
922132d3-9ca5-4554-be9d-3ca066fe9f15	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 17:27:22.376551+00	2025-12-10 17:27:22.376551+00
638ee532-62bc-454a-ba1e-be5144df49fe	1bbe551a-fa18-4df7-8897-2d15055d5c28	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 17:27:23.823631+00	2025-12-10 17:27:23.823631+00
0b63fb2a-98cc-43f6-842e-4b175897c1a1	7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	\N	2025-12-16 21:19:27.779776+00	2025-12-16 21:19:27.779776+00
61716c00-afa9-439d-a2b7-dde4323178b3	a8048ec8-1200-453e-b7cb-4a0dedb9eb89	46b4244c-c2ce-45ec-891f-7dd38d86e753	\N	2025-12-16 21:19:27.787693+00	2025-12-16 21:19:27.787693+00
02a2df79-2e79-4d7a-82e4-858c0e2e8791	aaf3c10b-93ec-44cb-9211-cbfc97c13ff3	dca4e684-c441-41fa-91d1-986fcbbf14c1	\N	2025-12-16 21:19:27.787196+00	2025-12-16 21:19:27.787196+00
193445f8-f1be-48e8-8977-dff7dc7d7500	a8048ec8-1200-453e-b7cb-4a0dedb9eb89	46b4244c-c2ce-45ec-891f-7dd38d86e753	\N	2025-12-16 21:19:57.902452+00	2025-12-16 21:19:57.902452+00
04934493-fc86-4180-a43f-d433eb0c7b71	aaf3c10b-93ec-44cb-9211-cbfc97c13ff3	dca4e684-c441-41fa-91d1-986fcbbf14c1	\N	2025-12-16 21:19:57.925477+00	2025-12-16 21:19:57.925477+00
64031704-c907-4f2e-b837-e05a6e92b1c5	7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	\N	2025-12-16 21:19:57.926056+00	2025-12-16 21:19:57.926056+00
9f099675-063e-4ef9-8b94-c5e04edeaca9	7cc5acb2-b51b-41ea-820a-a748ed7fc1d3	73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	\N	2025-12-16 21:29:01.65417+00	2025-12-16 21:29:01.65417+00
\.


--
-- Data for Name: secret_tag_junction; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_tag_junction (id, "secretsId", "secret_tagsId") FROM stdin;
\.


--
-- Data for Name: secret_tags; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_tags (id, slug, color, "createdAt", "updatedAt", "createdBy", "projectId", "createdByActorType") FROM stdin;
\.


--
-- Data for Name: secret_v2_tag_junction; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_v2_tag_junction (id, "secrets_v2Id", "secret_tagsId") FROM stdin;
\.


--
-- Data for Name: secret_version_tag_junction; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_version_tag_junction (id, "secret_versionsId", "secret_tagsId") FROM stdin;
\.


--
-- Data for Name: secret_version_v2_tag_junction; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_version_v2_tag_junction (id, "secret_versions_v2Id", "secret_tagsId") FROM stdin;
\.


--
-- Data for Name: secret_versions; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_versions (id, version, type, "secretBlindIndex", "secretKeyCiphertext", "secretKeyIV", "secretKeyTag", "secretValueCiphertext", "secretValueIV", "secretValueTag", "secretCommentCiphertext", "secretCommentIV", "secretCommentTag", "secretReminderNote", "secretReminderRepeatDays", "skipMultilineEncoding", algorithm, "keyEncoding", metadata, "envId", "secretId", "folderId", "userId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secret_versions_v2; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secret_versions_v2 (id, version, type, key, "encryptedValue", "encryptedComment", "reminderNote", "reminderRepeatDays", "skipMultilineEncoding", metadata, "envId", "secretId", "folderId", "userId", "createdAt", "updatedAt") FROM stdin;
387d5ef6-850d-4da3-b717-3cc65dc142da	1	shared	GHCR_EMAIL	\\xc3ae7570cba93cd0e973385f5a0559bdc98d4c58918f0b1b5d9add4ab59823e561dd51f8c6699992b4c8121d3b1061e25dbc4fd45433b6763031	\N	\N	\N	f	\N	\N	0fb46e27-45ae-4a28-b7c0-be8e0620d6a6	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
abd33f1c-be70-4ddf-8bc2-d9e338f1c14a	1	shared	GHCR_SERVER	\\x68c1de569ac1287afc134f11096281850881272b0e7d1f46011a7e9bfe0c23dc3c729f464ed7794ebe7292763031	\N	\N	\N	f	\N	\N	4a9782bc-5cb2-4d34-8618-9a5d6cf021ef	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
b85b891c-3ea5-4dee-8091-60c1357c3822	1	shared	GHCR_TOKEN	\\x0d618f9d03074872bfd2224efd01257949e849e51be491e14dde4edbc3eba60c74aa8641bd7efc3bf84bc0adfd050a9380b6ead618f3dd77785eec7f25fe403a77dd4242763031	\N	\N	\N	f	\N	\N	5e7d1da6-c4d5-4527-bcb4-3e9619777891	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
bd295f12-e92a-409a-889c-1ce3eb6eaba2	1	shared	GHCR_USERNAME	\\x5352b34166c48e1dcf8d175a22244bcd6f263d0a2cab909e3bad396f4ca64d21538fed650ef6208c83763031	\N	\N	\N	f	\N	\N	6feade35-dedd-4a52-9bcc-f0dacb29f93c	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
77372a79-e256-4ac9-a760-13785626be60	1	shared	JWT_SECRET	\\x6712f4f20135c3321ba26a04f8ad5ba705d98efab960aa5fd6cf1ae8564359290759fc55763031	\N	\N	\N	f	\N	\N	955131a7-4aff-4cb2-bf7a-4b09988a47f1	b3008a94-6937-43e8-ad16-74c17e9c18d5	\N	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
581165fd-156c-4976-80c9-628c178a4166	1	shared	GHCR_EMAIL	\\x506c3bb88f631a405dff5779d8ac84b266765c31aeece144da40225452c20c5103979c476595a12093cd973428c2ce9bba3320173fcbf3763031	\N	\N	\N	f	\N	\N	9eeb7e40-2160-4c2f-b904-3f222d13b3fd	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
16c23d3f-a7f3-46fc-bbd8-f8758e319914	1	shared	GHCR_SERVER	\\x1f5f42f4e9738ae08c4d8fdd5885ca3085f594ce3fa7cd56b2dc9020fac7a56f6d70212e0d3170994e4df9763031	\N	\N	\N	f	\N	\N	6d1de7da-26b0-424a-a8d1-50492f6defd2	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
7570897c-27d2-4957-912e-fcda9f9d0e54	1	shared	GHCR_TOKEN	\\xa5871e1244ca5f7c2625f1e0b7f840e594bfa6fa984b00dc61946e344befc61094ed2e2299b4b3136d80654ba5571debba8ee50487c012bdcd603ebb4bf6b8c5f0b77f50763031	\N	\N	\N	f	\N	\N	d73c53f9-7323-44ad-982a-d5bc35bae734	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
2b42f712-516f-4cb6-8224-361b45ae8c1a	1	shared	GHCR_USERNAME	\\xfd3a00e9dc3ec61ff7f6fc4630f44a97c03c630c54803b0a84afe342868615c9663f666aba0972f87f763031	\N	\N	\N	f	\N	\N	d3744560-8bda-4b87-bf9e-f75392aa538a	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
9843681e-a644-40fc-b3f7-15f53a99fe14	1	shared	JWT_SECRET	\\xb09b9e7ff6b41f362401c9900c451db15f30003ca91452c38ce1f6dffb3c3b4ee906fc02763031	\N	\N	\N	f	\N	\N	236c32a1-156e-4252-968c-b60106a0d690	9a38b5d6-0b73-4e67-87b6-a80561ace832	\N	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
edd47d6e-9e20-430f-94be-728f163e73f8	1	shared	GHCR_EMAIL	\\x49ed90c7d7cf6d674ac11aa9246b0b306b07e3b5afd6881bcd60a13ac9a4d581e7ffd48e3002cda996998ed260d513b5f89ebc31ab2468763031	\N	\N	\N	f	\N	\N	8a6801ca-cc08-46cd-aade-76eefb8b1070	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
040491d1-4b80-4762-a691-9abb9fef6242	1	shared	GHCR_SERVER	\\x82e0128e1d72fc22bc810fb569d8712b9321cc57ad78918239c42fe7fcee2fe6cfeadcd5b37fbf79bcb397763031	\N	\N	\N	f	\N	\N	3fe2381d-dc02-4610-840f-dc4d151d7ccc	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
bd087604-a9ac-4bce-8f5f-a4108fefbf7a	1	shared	GHCR_TOKEN	\\x74e588fae0e23fed44f68c16d823bf2a9fbea681f043ba448a5fa0ffae7497f4f2e7af75b7db3e09d2ee2c6fe156b9cb37af6e96b5a212b48b085599a9b4d0f22ccf4ad4763031	\N	\N	\N	f	\N	\N	c02f0f6e-2af2-4615-bee6-5c62c87c17e8	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
45da988b-0c76-4dbc-9b18-5407c1dbfba2	1	shared	GHCR_USERNAME	\\xc80770f8b9f108e9143c2d86da1e0e014e4a00c46e1d61c0d137e59e5e358a7ca96c14e8e67fc7a057763031	\N	\N	\N	f	\N	\N	d32b6dbf-a8fd-46e9-9f69-345e1057de63	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
10747c25-787d-4d2c-b333-4c1b75c59330	1	shared	JWT_SECRET	\\x522c1ac08e465dd905079ba705200038d4485aba48c7de73c6ac5124f911374f267d3cca763031	\N	\N	\N	f	\N	\N	72d68472-0a14-4e05-b2fc-ed32a35449d1	ee4196e1-ca5d-48d0-8dff-35475654cf98	\N	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
0cbbeb46-eba4-4e40-be2c-a5d1e97a2546	1	shared	ENVIRONMENT	\\xc281cba11e55164619a6b2f6e32c3394ff9b66279d69275dc3873ec7decbd0763031	\N	\N	\N	f	\N	\N	481b6e57-9fa1-4dcd-9679-41ee6e5cf48e	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
fca2e66f-4d28-4876-b196-c9f0f88fffef	1	shared	HSM_DB_ORACLE_DB	\\x93e197f421ac5f3f89ebbb9df02facaf50993040e4e7a3f5934cf33a1d0860fcd70a763031	\N	\N	\N	f	\N	\N	9bf0209c-51df-4095-b4fb-d733c017df21	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
739565c2-16b9-40af-9b9e-05c01b36a621	1	shared	HSM_DB_ORACLE_HOST	\\xc503e4d445274b181b09d1d41cfd5aab06d70b5a55c03b026054e530d76021361a25a540a4763031	\N	\N	\N	f	\N	\N	807d08b0-f74f-4c19-b371-cfab736241f7	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
ce955ff2-06fb-4e28-aa72-77a311d73dce	1	shared	HSM_DB_ORACLE_PASSWORD	\\x6786920de013f248245dae218c4526ccb22e1e4d780837ae7bf61678b1264c489ce6fc300c763031	\N	\N	\N	f	\N	\N	fcb487d3-211f-4a63-9c4f-58e1be30a685	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
b6ebbc72-3cd2-4f91-a810-d858b36932f5	1	shared	HSM_DB_ORACLE_PORT	\\x656c500ff2266ebd00614a83e9d621f65814079fd6bce97a4a07d932a8a9006c763031	\N	\N	\N	f	\N	\N	ff8d64c0-d88f-44da-a2d4-63f6b076daf7	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
067186d1-02a2-4994-ad1f-d39dcb736873	1	shared	HSM_DB_ORACLE_USER	\\xedc3bf8346e01633db62f562ee53b61af9bbc8f76c2f97a88f63e31b5584f4763031	\N	\N	\N	f	\N	\N	ed803480-6840-4d6a-a1c6-18fbda891cd7	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
02776bc3-699e-4aaf-b8c2-f6b897e09b99	1	shared	HSM_DB_POSTGRES_DB	\\x3902ad18d233314c61179f3a08fddb060e020c67746db313ab59a5866ed153763031	\N	\N	\N	f	\N	\N	2d5ee3d1-622c-447a-9b6c-f4786b8ab8f7	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
56ac6278-a819-48d4-b8f3-291a7a354b94	1	shared	HSM_DB_POSTGRES_HOST	\\x0a8553d6b861391f8db8c082a19e69bf8e7a79bf6f0d2b5aaaf618601c94d986e1ab25e909130b0d3f1749d1122de4763031	\N	\N	\N	f	\N	\N	c3ff5e7c-5bfa-4863-aa35-0deb60fc8ad9	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
13435208-966b-432b-a423-f474571c492c	1	shared	HSM_DB_POSTGRES_PASSWORD	\\xa298626950385baafb919445c2479a04cac2f9f0d04a9e03233687f317d9ed9dbda3ff3a763031	\N	\N	\N	f	\N	\N	74e596c7-cc37-479f-bc96-b5ead5c9fe6c	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
6f957543-9f09-4c50-b88a-074c40c5fd70	1	shared	HSM_DB_POSTGRES_PORT	\\xdfa2709858b8116761f2d7492a76923003765097eac5e708a99519147a1f946d763031	\N	\N	\N	f	\N	\N	c99fbc68-943b-458d-9580-6de5c882ef8e	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
f488e91a-7864-4c5f-91ea-ca1f45bfa4f6	1	shared	HSM_DB_POSTGRES_USER	\\x0d1018a518c0d7830c10c3f61bc392dbc7f63e92d56abdc5a3724a07b9ef776b293db658763031	\N	\N	\N	f	\N	\N	301ab46c-777d-455b-891f-932069619684	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
70b34c18-7d83-4b4d-8c83-b591a4429cdf	1	shared	HSM_DB_REDIS_HOST	\\xf681824108f4c86f74a21ae0268cac8f0a69ea206d9d5150b907d030c46920d318fe396aeaa0904bc8842b9b763031	\N	\N	\N	f	\N	\N	205e844b-fabc-480d-9af1-d8cdd33fcf67	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
5ee2ee3e-f358-4f59-9bd2-c45809458fe0	1	shared	HSM_DB_REDIS_PASSWORD	\\xb8b9f9b5b79068b00e85a55f5a59f078e33bbe26102eda4e2439003d9d063256d1763031	\N	\N	\N	f	\N	\N	c7f8d8cd-bc7d-46c2-bbd0-27d0921d0121	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
74451709-c9e1-40e1-90c3-66b397c70f02	1	shared	HSM_DB_REDIS_PORT	\\xecd80189d28e131ca71ab2499128a01cf930b6fb203e91af2db06c6d086eca90763031	\N	\N	\N	f	\N	\N	856f01e6-9812-4e19-a058-5c6b3b0e1a6d	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
f3ce2edd-a497-4baf-8f02-b1e22963ddd7	1	shared	HSM_DB_REDIS_USER	\\xf6e178d5d97f9d9ea12385a2be2162cb7a9c10c7903332946d6c2acf400d3e47c7763031	\N	\N	\N	f	\N	\N	32edb62a-53e4-46c3-af24-ad71c30c326a	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
30eb0f31-9dfd-470e-9f59-41d624444579	1	shared	TZ	\\xf5a1e409eff5ae14860dd0c6f2a4b92991a1f8c3edf3f274a706d98e38a5ae25b0ec3acfa8a30387ca0e63ddb4763031	\N	\N	\N	f	\N	\N	5f2a4ab5-d982-4c48-b318-4982d9536ba9	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
483b5a00-f643-4617-a760-7fda2cd7af59	1	shared	ENVIRONMENT	\\x92f40afe153d372f796bd97aee699c323bfd8b834e6eb1b1617caf60c4c94aade33b18763031	\N	\N	\N	f	\N	\N	a054a8ab-6ddb-4102-bbc6-62ec94aa59ae	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:36.634928+00	2025-10-22 15:45:36.634928+00
f723f200-c14e-4a92-b087-f9434c5efccf	1	shared	HSM_DB_ORACLE_DB	\\x54f4a8d751463075d1548a0bb9487c8c13c122cb40085ad9766c8c78b6dfaa8e68ec763031	\N	\N	\N	f	\N	\N	37e73fd9-3f79-4a80-b25f-c1a90bd85ee0	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:36.634928+00	2025-10-22 15:45:36.634928+00
e7546e8d-77fe-4156-84e7-59a6042ba4ec	1	shared	HSM_DB_ORACLE_HOST	\\x5b49e18656af20ad2e9af1c519c409ebeeaf497074d45a666aae34ac7c5e11dddf1887eac2763031	\N	\N	\N	f	\N	\N	143c477d-6ffa-4b4a-8303-26c99d42abaa	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:36.634928+00	2025-10-22 15:45:36.634928+00
a4a5ac5d-6fd8-49fc-b37c-ff3623288acd	1	shared	HSM_DB_ORACLE_PASSWORD	\\x9bc6b4588698aa38efd50e03774bc8640fc51d7f876a2728a2c9f471c659dba5bb0e826894763031	\N	\N	\N	f	\N	\N	0ff2dcdc-0b0b-4e63-bfac-1b91a30ceb5e	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:36.634928+00	2025-10-22 15:45:36.634928+00
8009827f-05af-421b-a3e1-adab304ca54c	1	shared	HSM_DB_ORACLE_PORT	\\xdabeab55ce595ec3313757625cedfc240fc352f7a99cdf5e1cd9a46b0247b3d6763031	\N	\N	\N	f	\N	\N	7e92f22f-23bb-4797-8a55-b4da86f11d37	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:36.634928+00	2025-10-22 15:45:36.634928+00
ac0db9dc-7510-4147-82e4-1008194bc1c4	1	shared	HSM_DB_ORACLE_USER	\\x255d16e531bb480b3dcb2cb12b966c7770b5f271ae35a196887ebd23c884e7763031	\N	\N	\N	f	\N	\N	dbf99b3b-92fc-438c-bc08-b90fe1503ba0	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:36.634928+00	2025-10-22 15:45:36.634928+00
98ad9b2f-0704-457f-b7a7-e25ccc37ce50	1	shared	TZ	\\xf4bdde394b299894d8ef2911c7c6a6845299fddda0e7f11c44848646d9d60a24bfa111d88edf06dc1e3c0bce24763031	\N	\N	\N	f	\N	\N	d00b4bb0-4d99-4a7c-bc2e-945956622270	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:36.634928+00	2025-10-22 15:45:36.634928+00
9d9e3a99-33a2-4d58-9d0a-26c92104105a	2	shared	ENVIRONMENT	\\x272795496fa4de281bdd6a51be144b6cbea7f6057d9ad1a0f8e9cca4c730e2826d9d7c763031	\N	\N	\N	f	\N	\N	a054a8ab-6ddb-4102-bbc6-62ec94aa59ae	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:59.271558+00	2025-10-22 15:45:59.271558+00
9c3fd485-eb3a-490b-b48b-333a372919c2	2	shared	HSM_DB_ORACLE_DB	\\x5478ef1304d9ade1084a9d31fcc18ccc7a7d14245759bff7980c4bbe65df2547cb57763031	\N	\N	\N	f	\N	\N	37e73fd9-3f79-4a80-b25f-c1a90bd85ee0	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:59.271558+00	2025-10-22 15:45:59.271558+00
2974a1b2-b0de-4935-b7a8-bd1317b21bde	2	shared	HSM_DB_ORACLE_HOST	\\x2de366032d8782d851af636936981a8b78fde121158f4b3f54645a0981bcfe3cf0937d405b763031	\N	\N	\N	f	\N	\N	143c477d-6ffa-4b4a-8303-26c99d42abaa	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:59.271558+00	2025-10-22 15:45:59.271558+00
7d7db4bc-87a6-43f7-b506-485d4adb98b9	2	shared	HSM_DB_ORACLE_PASSWORD	\\xc32aa53d9c3091c87afef2e7a20fb70d209b5f1f245f49dd502e567212e055c846823e8c58763031	\N	\N	\N	f	\N	\N	0ff2dcdc-0b0b-4e63-bfac-1b91a30ceb5e	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:59.271558+00	2025-10-22 15:45:59.271558+00
be98456f-a316-4a1e-b61a-3568395d22bf	2	shared	HSM_DB_ORACLE_PORT	\\xc204ad6bcd4f9003ce400a9d207834f18747789f08982cfc4a20bfa193fe7494763031	\N	\N	\N	f	\N	\N	7e92f22f-23bb-4797-8a55-b4da86f11d37	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:59.271558+00	2025-10-22 15:45:59.271558+00
473c1f86-1048-4398-97cf-7307148bfbee	2	shared	HSM_DB_ORACLE_USER	\\x2f133540ebd0785c3d089af85129b4d2dd7a17beeb1784257f26a5aa14c77e763031	\N	\N	\N	f	\N	\N	dbf99b3b-92fc-438c-bc08-b90fe1503ba0	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:59.271558+00	2025-10-22 15:45:59.271558+00
6bc434a2-c600-499e-87c0-6ccf40361357	2	shared	TZ	\\x4337fbb8b29ebeabb442e134446ffdbf110c4c8cc2dc8c83266a3e7d0e19260940f734aef4e3f83150cc3a2333763031	\N	\N	\N	f	\N	\N	d00b4bb0-4d99-4a7c-bc2e-945956622270	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:45:59.271558+00	2025-10-22 15:45:59.271558+00
15d67bd6-c6d5-4f0b-b404-fcafb283b0e7	1	shared	ENVIRONMENT	\\x1adef71ccc6c319f953be36a1ea105b2f4ad82dec0fe1921fa436fe9598f6327d7db26763031	\N	\N	\N	f	\N	\N	5cae6a38-7dfc-4cc2-9077-1fb5360a1b33	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
00f7ff7e-9454-4454-b3a3-8252088b1c01	1	shared	MINIO_PORT	\N	\N	\N	\N	f	\N	\N	53c329b8-0679-487e-8838-ccb31460911b	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:14.736868+00	2025-12-10 16:52:14.736868+00
ef3b5456-2d2e-4e96-bd05-721a247f9fee	1	shared	HSM_DB_ORACLE_DB	\\x35719506d6f2da900000afad88973127163965d40a2c2780561df5253ecaaf3d8736763031	\N	\N	\N	f	\N	\N	4509b70f-759f-4542-a64e-170a3edf376b	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
d630f143-3211-4785-8c35-bf0b2b4d25da	1	shared	HSM_DB_ORACLE_HOST	\\x6f3ab12049f84b6f67a23b95064307fd46e061d062f59e6701653d7652633f5af06df7d520763031	\N	\N	\N	f	\N	\N	18d44c3a-6da8-4b04-a141-ee5bb9febd6a	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
590afcbf-a281-4db3-95a0-24890160f859	1	shared	HSM_DB_ORACLE_PASSWORD	\\x81a374d52d7a7bc51926d47dc4d29368d89ac4ab3c3f39644048743960972000234d3bd83f763031	\N	\N	\N	f	\N	\N	92c79a38-aca5-469b-933f-373eaef18b83	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
053fb2fc-dbb0-4dbb-ba3c-59256f6eb2b7	1	shared	HSM_DB_ORACLE_PORT	\\x455d9a7cdce6fc12b968da9dbba39f43e2507d39744b69f5dece62d49ac0b96d763031	\N	\N	\N	f	\N	\N	77e6e6fa-3baa-46a7-84b9-a50d5a838752	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
f800834e-20d0-4d91-991d-51990b37c807	1	shared	HSM_DB_ORACLE_USER	\\xd13067c51d57f21ac1d1cd376ee7d324d6e038576c987376fbfded613865e6763031	\N	\N	\N	f	\N	\N	1c7355b6-ff4a-4dff-98f8-59cd82ef3561	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
0d3f3fe2-264c-41fb-8e8c-f7bc601fc20a	1	shared	TZ	\\xb19caec11025adbfd6cc162b5b75f8cabd125a7ca6be93002406cb5e100c43ac4f4a6979f4420957fca9055823763031	\N	\N	\N	f	\N	\N	12d9a0b1-7b35-4297-8340-0936f8467baa	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
759181c3-67db-4b94-8d65-7634e955f04e	1	shared	ENVIRONMENT	\\x3b3042b79d5073c68a1003898adff9896c7a6b947035fca07815277ad502e79c763031	\N	\N	\N	f	\N	\N	b9a4e186-a64b-479f-8f2e-b88d3e4a973f	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
53700e20-177e-4aee-b189-25886bdd1078	1	shared	HSM_DB_ORACLE_DB	\\x52015fc7fce354fe90d057d14afaa943be69a10d4bfe40337782f2383a6fc435277e763031	\N	\N	\N	f	\N	\N	6ffe8c9d-629e-4e8e-85e2-e7ea445cdd9d	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
b2647bf0-54f7-4348-9f31-c52b5377ff50	1	shared	HSM_DB_ORACLE_HOST	\\xc9c2d33e7754f88a413de792d603a12084a3f6629e2225704fca37a49a6c43e26e9c869123763031	\N	\N	\N	f	\N	\N	d7dc98e2-e297-4b0d-ad60-129fa48ff43c	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
84b319ed-3b4e-4068-8abf-ac9e496d1542	1	shared	HSM_DB_ORACLE_PASSWORD	\\x19394a7e63b605b1d6c4275add2906d70d0886da8772d7c92407cd165b0aaaf1d69b8618f7763031	\N	\N	\N	f	\N	\N	95e23636-0e31-469c-a39f-6da3dc68255e	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
53cacfa6-b868-427f-b0eb-5f34b12167a3	1	shared	HSM_DB_ORACLE_PORT	\\xe6d535c9ecc4d14fa37bcf9cffe2b0b499cc5487aacf17e7b62ee3c82af1c7d1763031	\N	\N	\N	f	\N	\N	413ac4bf-5e7b-47f2-8417-03853cf71308	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
776904ab-31a5-4f43-9a0e-b32607df0bb4	1	shared	HSM_DB_ORACLE_USER	\\x6eebfa9fd35ecd49e8fa3f9e67057433a4380b79e87077ce5ee11fe5342a5d763031	\N	\N	\N	f	\N	\N	7c884c34-76fe-499c-a551-284403a17b42	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
42d1bb4c-b4bb-4bf1-8cd5-3e58abc0687b	1	shared	TZ	\\xf5f8064d41685df8b13b4b485fac1d50fd4ec16953262e056864de55745ea9352829250a179cbed4627baefd9b763031	\N	\N	\N	f	\N	\N	9de96d3e-a842-417b-aa55-fc16ec694385	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
b1f6bcb7-03d5-4efd-9044-ceb9329d7e19	1	shared	HSM_DB_POSTGRES_DB	\N	\N	\N	\N	f	\N	\N	39318cb2-468f-43b1-92ad-7d3bcbdd9762	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:47:44.889499+00	2025-10-22 15:47:44.889499+00
f38b1bb5-2d5f-4b47-aa90-760a959ae1bd	1	shared	HSM_DB_POSTGRES_DB	\N	\N	\N	\N	f	\N	\N	f8d66b2a-e360-4880-8888-09aba6e54402	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:47.602063+00	2025-10-22 15:47:47.602063+00
bf16613a-e1a1-4770-879d-ce39a3475340	1	shared	HSM_DB_POSTGRES_HOST	\N	\N	\N	\N	f	\N	\N	7a0f7aa2-1090-48a0-9a6c-ee9341760557	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:47:58.198245+00	2025-10-22 15:47:58.198245+00
f3e78c0a-e119-4dc2-8169-045b27a5a7b3	1	shared	HSM_DB_POSTGRES_HOST	\N	\N	\N	\N	f	\N	\N	a1a07c94-a74c-46b4-af8e-d47eb09ccd52	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:47:58.487714+00	2025-10-22 15:47:58.487714+00
fa1dcbc9-705a-4fa7-be84-3e9955e79090	1	shared	HSM_DB_POSTGRES_PASSWORD	\N	\N	\N	\N	f	\N	\N	939f3f8d-e322-4c6d-8aaf-0828c6f9255c	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:48:08.702795+00	2025-10-22 15:48:08.702795+00
5e41edba-d18e-473a-80f6-ce485511ad1a	1	shared	HSM_DB_POSTGRES_PASSWORD	\N	\N	\N	\N	f	\N	\N	4507343d-0d9c-40f3-9fbd-5a9d3f832928	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:48:09.166864+00	2025-10-22 15:48:09.166864+00
5bd67143-d039-4d00-8f68-8dd6e5474352	1	shared	HSM_DB_POSTGRES_PORT	\N	\N	\N	\N	f	\N	\N	84bc898f-3d8a-46a6-ab0d-e75d69487a5b	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:48:15.375968+00	2025-10-22 15:48:15.375968+00
c3ca5101-f966-4119-bbbe-7f368e7466df	1	shared	HSM_DB_POSTGRES_PORT	\N	\N	\N	\N	f	\N	\N	7a8d57a1-deef-48f4-bd38-bf8cbf16d9d5	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:48:15.78646+00	2025-10-22 15:48:15.78646+00
7564b13d-7b7e-44ce-b7ff-b80829c89d2b	1	shared	HSM_DB_POSTGRES_USER	\N	\N	\N	\N	f	\N	\N	eb095caf-0105-4ee4-8fb8-90ee00fbc72e	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:48:26.683081+00	2025-10-22 15:48:26.683081+00
70a33671-d314-40c9-8b84-bd8b869720ba	1	shared	HSM_DB_POSTGRES_USER	\N	\N	\N	\N	f	\N	\N	2e86e860-8ca5-4aad-930a-683234c42103	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:48:27.104532+00	2025-10-22 15:48:27.104532+00
17100167-0f3f-41e8-b028-bddac3132dbd	1	shared	HSM_DB_REDIS_HOST	\N	\N	\N	\N	f	\N	\N	0c5b9370-3367-4f1b-b6ee-d150e183f7d9	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:48:35.131062+00	2025-10-22 15:48:35.131062+00
87accdda-6a67-4123-b6c2-fc2697ce6876	1	shared	HSM_DB_REDIS_HOST	\N	\N	\N	\N	f	\N	\N	dcf10944-d3f7-455d-ae54-d5dd02a81fc1	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:48:35.650747+00	2025-10-22 15:48:35.650747+00
cfac54dc-9d2e-4dd9-80af-1d83402afa58	1	shared	HSM_DB_REDIS_PASSWORD	\N	\N	\N	\N	f	\N	\N	268fdfde-b09b-473c-bfa2-6f2cdc9280e8	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:48:43.305494+00	2025-10-22 15:48:43.305494+00
7ea93931-2f6c-4c5f-9db7-2f5748f2e091	1	shared	HSM_DB_REDIS_PASSWORD	\N	\N	\N	\N	f	\N	\N	f3456c66-c295-4f14-95c8-6eb4a6f5c005	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:48:43.654849+00	2025-10-22 15:48:43.654849+00
0a8aaa9a-2e0a-47db-a1e2-50533850b514	1	shared	HSM_DB_REDIS_PORT	\N	\N	\N	\N	f	\N	\N	d7dd4577-2b15-4e62-b718-cdb763235fc0	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:48:51.319462+00	2025-10-22 15:48:51.319462+00
2098a6c3-456e-45c1-9e1b-40b58e442d8c	1	shared	HSM_DB_REDIS_PORT	\N	\N	\N	\N	f	\N	\N	5e390845-64dc-44b1-ac62-004dc016d73b	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:48:51.710434+00	2025-10-22 15:48:51.710434+00
fea73af7-dc70-4ada-a8ad-b58f0a4a9903	1	shared	HSM_DB_REDIS_USER	\N	\N	\N	\N	f	\N	\N	c1aff9ad-72f1-44b2-b006-48e1ab24e02c	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 15:49:02.47159+00	2025-10-22 15:49:02.47159+00
359c312c-2289-4e1e-beae-0665ae696946	1	shared	HSM_DB_REDIS_USER	\N	\N	\N	\N	f	\N	\N	e0654ec5-c913-4ccb-9779-6ce74f91909d	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 15:49:02.859626+00	2025-10-22 15:49:02.859626+00
c1a2fff7-4af5-4084-9501-73743c64a132	1	shared	JWT_SECRET	\\x7f3c3583cb8190d1315b6ceabcaff3576d82d61acc80b981a7de865e7d21d0be26763031	\N	\N	\N	f	\N	\N	bd45e77f-94cf-4b7a-8bab-f43d1ad0ca9d	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 19:08:40.437349+00	2025-10-22 19:08:40.437349+00
842b5661-6d05-46f8-a4b5-c28e471fb2e2	1	shared	JWT_SECRET	\\xb8cd129b82591f39b8ac10db58c5ffac957043dec54f81bcff49200379d22c35e3763031	\N	\N	\N	f	\N	\N	12956605-eb20-4815-b613-103a631c0bd8	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 19:08:40.48241+00	2025-10-22 19:08:40.48241+00
272af30b-6cd3-4dd5-aa91-21f2c5056895	1	shared	JWT_SECRET	\\x7aaa7020127ee30971f8f8461b530199769db8be5c518d878b5117514826a48a08763031	\N	\N	\N	f	\N	\N	74d58eb4-4dd3-4b1d-95f1-1ea5d932de9c	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-22 19:08:40.616567+00	2025-10-22 19:08:40.616567+00
7cea4a01-6d3c-4f13-86f4-5e8ac44c4298	2	shared	JWT_SECRET	\\x2780de1f3c50240ea8e2f6af80a1161df10d288f6333dc0431809e02f6a57120181634db0a6a496d0d8a12d07b57d5dece9c25c4f665f76b75285f20108cf3d4b06d0d53044c2982cde50ec54614eb0782198b953a60d5fa62c435b15ad77d5452506dcda75f219cc96c30a2cf027c9a196aac0dc61c4f06396b15e5b53aa3000ae4b36e85db4c19b6eecb173cb8ac21021e6e33e31baf48313cbbaa763031	\N	\N	\N	f	\N	\N	bd45e77f-94cf-4b7a-8bab-f43d1ad0ca9d	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-22 19:09:36.157744+00	2025-10-22 19:09:36.157744+00
d85c9434-3824-4de7-ab00-88e9708b80da	2	shared	JWT_SECRET	\\xf9513db05f2fa9abb1ae7dac701034d89f6dd3799ef309086760f65431f890dd5cfcbe457dd3be55435c8a92702c4bd255679ae3b711f34d2a5c8188158f15bbc684a0890d1b37a4d3fa7f96ac48f0eea6be7fe8419250ccf9160a5829269e8b0aca85dee41a8a2f9b7c24607347aca040303e60d39f07f481ebd15885c3b31e37e563f29594ed41f82cf4e4012d9933f5431f397dc749f22fcbd6a3763031	\N	\N	\N	f	\N	\N	12956605-eb20-4815-b613-103a631c0bd8	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-22 19:09:36.852731+00	2025-10-22 19:09:36.852731+00
7188dbfb-d2f9-4d2e-8bc9-6b94b001a7dd	1	shared	AT_JWT_SECRET	\N	\N	\N	\N	f	\N	\N	6db71f89-6628-4785-b616-6fcc88d6f5d3	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-23 17:35:42.641422+00	2025-10-23 17:35:42.641422+00
958183ef-1358-4745-94ec-6d72b11ff7e6	1	shared	AT_JWT_SECRET	\N	\N	\N	\N	f	\N	\N	42d0ba95-57e6-4626-8484-4a044dfff1f1	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-23 17:35:42.708282+00	2025-10-23 17:35:42.708282+00
0855c644-c225-4635-b34a-fc4abc291236	1	shared	AT_JWT_SECRET	\N	\N	\N	\N	f	\N	\N	56d0a993-664c-4535-a1fc-077cd07f06c2	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-23 17:35:42.755673+00	2025-10-23 17:35:42.755673+00
45ab2fd7-a5a1-475e-b544-152d6720df33	1	shared	RT_JWT_SECRET	\N	\N	\N	\N	f	\N	\N	a9fbf5f6-5087-4104-be76-2334ecc92d80	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-23 17:35:57.302636+00	2025-10-23 17:35:57.302636+00
e84ad97b-a61b-46f0-9cdd-523006f542eb	1	shared	RT_JWT_SECRET	\N	\N	\N	\N	f	\N	\N	06e337f2-0a06-4e0b-9f49-d3efd09ff23c	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-23 17:35:57.38247+00	2025-10-23 17:35:57.38247+00
d50935b3-32cc-4353-bce3-de0d3617b02f	1	shared	RT_JWT_SECRET	\N	\N	\N	\N	f	\N	\N	18f239e3-f659-47fb-9984-0f098c4fa9b5	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-23 17:35:57.450889+00	2025-10-23 17:35:57.450889+00
c797a155-accb-4272-82dd-844f650ed59a	2	shared	JWT_AT_SECRET	\N	\N	\N	\N	f	\N	\N	42d0ba95-57e6-4626-8484-4a044dfff1f1	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-23 17:36:09.299784+00	2025-10-23 17:36:09.299784+00
0c89ef3b-ae6a-45a3-8971-2a2738d3d69e	2	shared	JWT_AT_SECRET	\N	\N	\N	\N	f	\N	\N	56d0a993-664c-4535-a1fc-077cd07f06c2	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-23 17:36:09.312248+00	2025-10-23 17:36:09.312248+00
afdbfef4-de59-4ee7-a46a-eddf4a9de311	2	shared	JWT_AT_SECRET	\N	\N	\N	\N	f	\N	\N	6db71f89-6628-4785-b616-6fcc88d6f5d3	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-23 17:36:09.355027+00	2025-10-23 17:36:09.355027+00
663ea842-bff5-4313-8e24-c81ee0c97163	2	shared	JWT_RT_SECRET	\N	\N	\N	\N	f	\N	\N	18f239e3-f659-47fb-9984-0f098c4fa9b5	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-23 17:36:18.781504+00	2025-10-23 17:36:18.781504+00
2518cbb6-7119-4af9-927b-6cfb5bf4c19e	2	shared	JWT_RT_SECRET	\N	\N	\N	\N	f	\N	\N	06e337f2-0a06-4e0b-9f49-d3efd09ff23c	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-23 17:36:18.788414+00	2025-10-23 17:36:18.788414+00
9d8ce2d8-0fae-4514-aefd-487f2fbb5923	2	shared	JWT_RT_SECRET	\N	\N	\N	\N	f	\N	\N	a9fbf5f6-5087-4104-be76-2334ecc92d80	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-23 17:36:18.791711+00	2025-10-23 17:36:18.791711+00
41b7a346-3ed8-4af2-9110-62d90f492343	3	shared	JWT_AT_SECRET	\\xb55787317be0d81df009ade0489347e0874b9178271eb723b9189a298edb8b72d0763031	\N	\N	\N	f	\N	\N	42d0ba95-57e6-4626-8484-4a044dfff1f1	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-23 17:36:29.895846+00	2025-10-23 17:36:29.895846+00
059a3f39-a329-4d81-a1bc-a5077ebc741a	3	shared	JWT_RT_SECRET	\\xab93b6ba6e63a7e8094f7563d4cd0143db012ac3e5b72d98069509083601597a73763031	\N	\N	\N	f	\N	\N	06e337f2-0a06-4e0b-9f49-d3efd09ff23c	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-10-23 17:36:30.945353+00	2025-10-23 17:36:30.945353+00
2652386b-b7d7-41d8-ab9f-22e3a2e0357d	3	shared	JWT_AT_SECRET	\\xc13fc069b05806509f53fcf8cba0d17001fc3ce2c34a91419df9919d489a0b91a569998bd926f1494716ee747fe4908f71f598384b8d113a370ec779a467f3dda8d81fd81354f31e65a63224b6ba612ed9f9ad8cd1a81720b9498a2dcd9dbabbc5bca66692ea4d9cdbac925089e5e10bc28344f41ac6d3bef7fe92b1a729aa4698337a976ebb02f1ee378167c91fe53d9181745a2449fff792cd2c06763031	\N	\N	\N	f	\N	\N	6db71f89-6628-4785-b616-6fcc88d6f5d3	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-23 17:36:42.566867+00	2025-10-23 17:36:42.566867+00
5c9adfa1-cd6c-4f5e-8522-c4edb8cc8883	3	shared	FRIGATE_RTPS_USERNAME	\\x9ed0548149256eec97c043f064b614ab37354b670d78a366d59a677f433489b4a2604e9b52763031	\N	\N	\N	f	\N	\N	377396f2-51fa-4c56-ba55-520968950a40	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:14:21.847433+00	2025-12-08 18:14:21.847433+00
9906114e-2eee-4dc3-a9de-1aff750dfa9c	3	shared	JWT_AT_SECRET	\\xf004ffecf16e4756804bf307e91b60c426d30677608997f32c64cc400b2e35653974c228d4d8191652c90fa52a9cef3e67108541835ad5e37a9debe182b9a22003fa9a9ca173e0050ece3ef8d9db854c0c65222654e8b8b263e52443f991bd4e4fb6403a673ae71e60baabfa3df3d0ea1219baf033701d219b350c3388ad5de39135ec84d555f14e9300f43c8b4705678218d5154d505cdeaa102b23763031	\N	\N	\N	f	\N	\N	56d0a993-664c-4535-a1fc-077cd07f06c2	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-23 17:36:47.935739+00	2025-10-23 17:36:47.935739+00
c3c5cba3-9ea3-4561-8d45-86170d045b3c	3	shared	JWT_RT_SECRET	\\xb89eec8c454229fecc1395827e06a73af194f1032781bdb38d400cd6162af50ad9a60cb4025854a31f9f99dbe504dbc58b18789e160f71c1bff22d02974a22dab6437e6ff0179d0e188b12afed4d13882c26d3b4643dd61fde6db803b4e920793343c0566916ab44f3171c01c7c8237b4948257282beeb88fec77a07d8ad524d99304b9495c5dcbacc5091c911d5b5a26e57040b578506d9eac9de98763031	\N	\N	\N	f	\N	\N	18f239e3-f659-47fb-9984-0f098c4fa9b5	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-10-23 17:37:18.766779+00	2025-10-23 17:37:18.766779+00
5bf40fb9-9c63-4bf4-ad3d-04b54a76b388	3	shared	JWT_RT_SECRET	\\xf9e195607274742a0ec61e49226decabc92094b53779b2d547c70ec5cc4ee4dba134d2f64e8128d0713d635d5b59eef5488c64fef43a4797973d3ff95e8fab4431ba0372877199e675643b6a1db0ab162c8b25c1de51e5d71b7bdd1a8d8be50cf3e3c2505c17bc9fcb16296edc76725817f1290c6aa4d44466e2edc3b63a29b7d95df91b612aad62461d9634bfbd25ff42e9818d087a5b338aa1535a763031	\N	\N	\N	f	\N	\N	a9fbf5f6-5087-4104-be76-2334ecc92d80	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-10-23 17:37:19.420461+00	2025-10-23 17:37:19.420461+00
f38033cc-64e3-4697-b87c-c3639736f113	1	shared	OPENROUTER_API_KEY	\\x4a01a17864a4ff9b20f7686a47578fcfe32202bb3114db744714a0806bec0949ab3389790f140a70137c8f3a39b14abaf53b6fa998863e49142e9871a003f4d25c07fa0a657a1d22e8790163814d46155f0164a5035e9cd1a00342901d1d2659bd81a60224763031	\N	\N	\N	f	\N	\N	b70d991a-95b2-4f74-9c79-da202be4a4b1	e4511410-f276-46e6-82bf-074363964703	\N	2025-11-11 19:17:13.553519+00	2025-11-11 19:17:13.553519+00
729a9abd-5173-4dd6-afa7-77827ce58f8a	1	shared	OPENROUTER_API_KEY	\\xaf2eb8a1e4ca4c6ee7bb906c79f76529984ffc518d2049c05be8d79a2a32eb53a9bed34a9b5462991f4922b6d3ae3eb578e35801825b4e75aebe1c7a972b9d5b1a4d42333e593c262e82bdb51b0e515f38f24917b331bad31fbf0e5d75e14c7b4165c0ea18763031	\N	\N	\N	f	\N	\N	4bd4738a-38e6-4e60-a7ad-ed60e96cf856	05c2e293-0bfe-4acc-81cb-0b04ee0a5566	\N	2025-11-11 19:17:13.557639+00	2025-11-11 19:17:13.557639+00
0d3abf37-e63e-4af7-ad40-9eefec29770f	1	shared	OPENROUTER_API_KEY	\\x4b2065820405bd47984726c70da0013e1c71d3fc083fe2f6464e00c76a8accd4427441a691a512441ea3f451d16490809fab93c03e2ca75307eb458294351c562b832bb5375fd161c9bad8f5dca7dbc306f3088305bdbafe15b897d95d5ef77468c6957fd8763031	\N	\N	\N	f	\N	\N	b56618c7-256e-48ee-aa3b-d63b450a71ee	8ae0e6fa-1c96-4b4e-a9c3-9f64c63f6ebe	\N	2025-11-11 19:17:13.56251+00	2025-11-11 19:17:13.56251+00
9f6f671b-8447-4c15-ad9e-a46c1460d3e0	1	shared	SWAGGER_FAVICON	\\x803cf61245787b6f8596bc262f5c599b51c7bf6dc6afc4d91f2277658966d6ce796691b51639e705d3c184a2efc6726213259bcef901c084e0065ad44d0dd2467d464585e2b979b495fe4501e4ba8bd8873b161a19dea69f6c5ddce040db9136517a6eb5fbb1f2d9f7c75fd554165c9971128aaefcfcb71e68f9538cee3b2c633bee86a1889a9bd827ee763031	\N	\N	\N	f	\N	\N	7b836f0a-64f1-48f7-a121-0e0c93b97bac	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-11-13 19:48:58.214408+00	2025-11-13 19:48:58.214408+00
790d025b-75be-454b-b929-99a030355692	1	shared	SWAGGER_FAVICON	\\x4d451ef9e8eaa2bd6abd79f6bdea4c26f6e463f16ca8bf141e0a25a24fbf1ad6084947d6fe0c1f749c9fae2177ac0380a290a43dfc99edf8f03f98bb058594738a2b3164dcc3334860198913aa2d9663281b7d973ff6193ac29d4b9337f1840a60a384b2c5cb3e8729de19fddc64e8f9e25ced4af4a6ae7820e78baa1d5d028016e53760684d33d0962d763031	\N	\N	\N	f	\N	\N	a2acc658-1236-4be6-bd89-0462d9e2f36e	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-11-13 19:48:58.327783+00	2025-11-13 19:48:58.327783+00
245b6b90-dce1-4d39-958e-cda5790e3bb2	1	shared	SWAGGER_FAVICON	\\xa4a74ff5e93e9a539919a7e5baeb5c6a9791283743326b6f7348cc9f8b70e935b44fe88bfda95fca12f7b1a8f6c21295588904d5cc2d3229d8961584fc307613d6198a3f8af219df1fe41b27cfe4aebbcda58095a25d792c13fe611396d8e94b8ae5c0f8f9b6337e7d472d675e751aae87c6170cf97c9abab93b3e318e251a9919f67382568c6df6c5b1763031	\N	\N	\N	f	\N	\N	0ba2e93d-337a-450f-be59-90ef9a4f0354	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-11-13 19:48:58.424705+00	2025-11-13 19:48:58.424705+00
52632d8a-533b-496a-95f3-c1ac746d10dd	1	shared	SWAGGERR_SITE_TITLE	\\x7e98c15eae705b782c757cef393ec300c59614a8226fe665e3d4f78f4fd7ea595b4daf7b79c8d276e8bfe389add44f0ca26f9c927ede6a335a763031	\N	\N	\N	f	\N	\N	fc8711bc-3242-44b2-b242-f88aa63cd5e4	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-11-13 19:49:18.844206+00	2025-11-13 19:49:18.844206+00
830cdde6-2924-4b7e-a12f-94e20d72f2bc	1	shared	SWAGGERR_SITE_TITLE	\\x07878ca8f2c78d1f3b9d1ddd001d510db1d2d64dfeed4fcc421816bf1f0a29e87c022b712fc091280112d576516dc7071d2bdb9d9c9b74e58c763031	\N	\N	\N	f	\N	\N	65a363d7-68db-466c-83e7-7a1d72a42334	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-11-13 19:49:18.892096+00	2025-11-13 19:49:18.892096+00
cee2f551-1841-4c84-ae30-6555196277ba	1	shared	SWAGGERR_SITE_TITLE	\\x1bd6f3798fde6474ee76ebadb7cbd8e59333660c9c187e0d9eee6f6a32d783fce120d29a57e029457913d87bf653be3e39c954d72d34a53aea763031	\N	\N	\N	f	\N	\N	1394efef-0624-48b8-89ec-2daf7438a22c	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-11-13 19:49:18.891875+00	2025-11-13 19:49:18.891875+00
0cd08ff6-5795-4f84-8484-342a4ba424b2	2	shared	SWAGGER_SITE_TITLE	\\xd74ddeae016c85bb869ef9348c0333db985611dfc9ff1361c77c3ea429799964b19da593535e4eedeb12d1897c75c55e34cfbf3bc9af452ec2763031	\N	\N	\N	f	\N	\N	fc8711bc-3242-44b2-b242-f88aa63cd5e4	04c8a5bb-668a-4207-a189-3549854ddfce	\N	2025-11-13 19:53:54.299754+00	2025-11-13 19:53:54.299754+00
f72a55a5-9acf-4f63-9b84-d8f98a77a528	2	shared	SWAGGER_SITE_TITLE	\\xdd5876a9ef6ceb56c2726a053e1b50481e908f06cafc2ebe26be4a61ff20617c27dfe0ddb7a17936ba6d39169ba561fc54994c1832c1f62b42763031	\N	\N	\N	f	\N	\N	1394efef-0624-48b8-89ec-2daf7438a22c	2707578f-df91-451e-80b7-f2fc488e815a	\N	2025-11-13 19:53:54.325722+00	2025-11-13 19:53:54.325722+00
8a30f366-a7a8-444a-8cf6-ec9c7104efa0	2	shared	SWAGGER_SITE_TITLE	\\x7b983586d655084b01e9e0f53993a6989b1d6be409b6acfa150cc4c7e7495b86d813dcd240609fe05ea09dc142842d086a11dbd91dfe1feb98763031	\N	\N	\N	f	\N	\N	65a363d7-68db-466c-83e7-7a1d72a42334	5bc6e6bb-7529-4395-abdf-bd66d0adb699	\N	2025-11-13 19:53:54.327055+00	2025-11-13 19:53:54.327055+00
b8c07202-de25-4427-94fe-485fc0b8baab	1	shared	FRIGATE_USERNAME	\\x4c08546575d55c1934f0e8a2f48ab6d26f514f226aa9105637bb96585adc897712763031	\N	\N	\N	f	\N	\N	377396f2-51fa-4c56-ba55-520968950a40	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 17:39:22.916864+00	2025-12-08 17:39:22.916864+00
b24d1953-d6e5-4681-b5ed-6583594a8214	1	shared	FRIGATE_USERNAME	\\xf9fc323b938f369c11df0326194df2da12257fa51a4e28c417fb93f376806a28de763031	\N	\N	\N	f	\N	\N	ecb331ab-05ef-49e1-99a5-2d0664349759	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 17:39:22.947442+00	2025-12-08 17:39:22.947442+00
c4cced6a-3a5b-493d-9501-9ea4b37cd57a	1	shared	FRIGATE_USERNAME	\\xfa1396a856fb8108fd0a64f682184c0cf60933144ab7d50822a2c23a92e3539bb0763031	\N	\N	\N	f	\N	\N	48227d56-f097-4545-af4f-faeb8366f649	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 17:39:22.953181+00	2025-12-08 17:39:22.953181+00
66ed1436-b036-44b0-9272-08f5a8cf6645	1	shared	FRIGATE_PASSWORD	\\xc594d9c7075b98902a0aa580c84056e6a0bc6e4b65dabf43297f6edac5dcdd642245d0f3763031	\N	\N	\N	f	\N	\N	0544db56-558c-4290-bdce-b139cae21e6a	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 17:39:39.310792+00	2025-12-08 17:39:39.310792+00
eda3f03f-121e-4efe-ba2b-e046a45ab826	1	shared	FRIGATE_PASSWORD	\\x3aacfcc25b81eaa2f44c3cd10cd2c0bfdbc5a1d05c3e757fb9cc4884a3352ea422d415dc763031	\N	\N	\N	f	\N	\N	0b4c3c2f-a2b3-4fa5-bfe4-b04a1120933b	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 17:39:39.319803+00	2025-12-08 17:39:39.319803+00
fc795d37-ad46-4721-a884-6efa6a9859d9	1	shared	FRIGATE_PASSWORD	\\x7bdb158caadafae3da00cbc4bc3c6e77d9686cce0dc8750bebe2c83188cbbb715f1f4a33763031	\N	\N	\N	f	\N	\N	82252a1b-031d-47d4-87b2-9466d250a8c9	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 17:39:39.321736+00	2025-12-08 17:39:39.321736+00
ce80af2b-ad61-41ca-8f03-6923b2adf6e2	2	shared	FRIGATE_RTPS_PASSWORD	\\x0a4b59bc6f8340f16fdb583027dc96bb65debeb8e797ab4e3d05a107a1de2a8d363120a3763031	\N	\N	\N	f	\N	\N	0b4c3c2f-a2b3-4fa5-bfe4-b04a1120933b	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:12:19.857944+00	2025-12-08 18:12:19.857944+00
85008cc4-d505-46ad-ae58-612341415494	2	shared	FRIGATE_RTPS_PASSWORD	\\x2e3d106768101093fea2a5d775f4de5bd10dd97391607d959a5457609a8b54320c2386df763031	\N	\N	\N	f	\N	\N	0544db56-558c-4290-bdce-b139cae21e6a	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:12:19.865711+00	2025-12-08 18:12:19.865711+00
f6d0b0f6-38d1-48e9-855b-d0a59c0a34e4	2	shared	FRIGATE_RTPS_PASSWORD	\\x6adb5ae4b6f30619922798375e3e75d655f167534d9bda300a14f026184f5be7d707bbab763031	\N	\N	\N	f	\N	\N	82252a1b-031d-47d4-87b2-9466d250a8c9	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:12:19.884094+00	2025-12-08 18:12:19.884094+00
31696d2c-b485-412b-9df7-8e1019688f7f	2	shared	FRIGATE_RTPS_USERNAME	\\x35fa405abd1ead2a74393dc08afc37be13093bb92e3faf8c43a2295e843461a56a763031	\N	\N	\N	f	\N	\N	48227d56-f097-4545-af4f-faeb8366f649	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:12:26.754007+00	2025-12-08 18:12:26.754007+00
19402d32-35dc-4f46-b86d-18b8defeb418	2	shared	FRIGATE_RTPS_USERNAME	\\xf0322b538f4d47f51c4d5db287bd0b6c054e874610a4a55637bfdcfc20b9292990763031	\N	\N	\N	f	\N	\N	377396f2-51fa-4c56-ba55-520968950a40	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:12:26.753365+00	2025-12-08 18:12:26.753365+00
e1e76de5-0d39-42c6-b512-2769f1b5f510	2	shared	FRIGATE_RTPS_USERNAME	\\x41237b68827014acf34511530cb555dc87b09cd398c75be5f4a88370adb88f1262763031	\N	\N	\N	f	\N	\N	ecb331ab-05ef-49e1-99a5-2d0664349759	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:12:26.753477+00	2025-12-08 18:12:26.753477+00
755426e6-e7d0-4432-816e-43e267eeb4aa	1	shared	FRIGATE_RTPS_TOMO_PASSWORD	\N	\N	\N	\N	f	\N	\N	aa753dd9-16cd-407d-a853-dfc1616c38ea	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:12:48.510383+00	2025-12-08 18:12:48.510383+00
6e021572-c7df-48eb-9665-92302406fb55	1	shared	FRIGATE_RTPS_TOMO_PASSWORD	\N	\N	\N	\N	f	\N	\N	d38b053e-91c4-4c47-ac83-d76314d57989	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:12:48.535949+00	2025-12-08 18:12:48.535949+00
3ad6b237-b8be-478c-aa7a-9e024d69f33d	1	shared	FRIGATE_RTPS_TOMO_PASSWORD	\N	\N	\N	\N	f	\N	\N	6a2ba448-9adb-4eb5-8fe9-59ea572cc1c5	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:12:48.536788+00	2025-12-08 18:12:48.536788+00
5d0eab25-e260-49ff-be2e-6e59dbc613fe	1	shared	FRIGATE_RTPS_TOMO_USERNAME	\N	\N	\N	\N	f	\N	\N	0c2d9e3d-6533-419a-bd02-4830593dadcf	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:13:08.118404+00	2025-12-08 18:13:08.118404+00
4dd9bf34-3a05-4c8f-89bb-e63421e3902a	1	shared	FRIGATE_RTPS_TOMO_USERNAME	\N	\N	\N	\N	f	\N	\N	33e70947-1ac7-47b5-a43a-4af30c6ddf94	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:13:08.144798+00	2025-12-08 18:13:08.144798+00
7b3e66d2-c01d-4a8d-ac61-448c569a7197	1	shared	FRIGATE_RTPS_TOMO_USERNAME	\N	\N	\N	\N	f	\N	\N	5692fef6-09c9-43d8-94df-25c77d145cbd	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:13:08.145758+00	2025-12-08 18:13:08.145758+00
0861f48e-08cc-4766-94c9-06ca4a322544	3	shared	FRIGATE_RTPS_PASSWORD	\\x1276bd3b2d7b24951b42246322ee682227e34a3a4c943ad084c54fa90db74d62f922d873db8679763031	\N	\N	\N	f	\N	\N	82252a1b-031d-47d4-87b2-9466d250a8c9	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:13:27.540197+00	2025-12-08 18:13:27.540197+00
709918a8-a0b3-4656-86d6-c7dc5aa1190b	3	shared	FRIGATE_RTPS_PASSWORD	\\x84716191aab70f52de9caa5bcbc32babcd62fcf2cfa59d8409579dc4e8ec00ede7dfa2a95471d9763031	\N	\N	\N	f	\N	\N	0b4c3c2f-a2b3-4fa5-bfe4-b04a1120933b	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:13:27.839485+00	2025-12-08 18:13:27.839485+00
c8e940ae-9816-4b6d-8453-bac9c2722f4b	3	shared	FRIGATE_RTPS_PASSWORD	\\x64b189097ee6e7960725b0cd02bba5efd6f1f36b0702497a6441bec9ef9eafd67648c397d63968763031	\N	\N	\N	f	\N	\N	0544db56-558c-4290-bdce-b139cae21e6a	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:13:28.20142+00	2025-12-08 18:13:28.20142+00
94450338-78b3-42c9-a9dc-321d2dafe56b	2	shared	FRIGATE_RTPS_TOMO_PASSWORD	\\xa9378a8f48f96fcae98416c4ac173761b15e6f2d1638eb4ab2cdbcaf53f89f9a763031	\N	\N	\N	f	\N	\N	6a2ba448-9adb-4eb5-8fe9-59ea572cc1c5	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:13:47.775701+00	2025-12-08 18:13:47.775701+00
1fec7905-8299-42ac-8092-b308a0dfac31	2	shared	FRIGATE_RTPS_TOMO_PASSWORD	\\xbd02d99e26b2bf71226e2b358eb447949dc471cbf7d0f0168d83046f43978b91763031	\N	\N	\N	f	\N	\N	aa753dd9-16cd-407d-a853-dfc1616c38ea	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:13:48.102826+00	2025-12-08 18:13:48.102826+00
09354fff-dc5a-4766-92bc-1d507df014fe	2	shared	FRIGATE_RTPS_TOMO_USERNAME	\\x4fc90b9fcb3414b0b944d7b7038eeab94728406ae692dcc28c958473f83a23295039743d746e763031	\N	\N	\N	f	\N	\N	33e70947-1ac7-47b5-a43a-4af30c6ddf94	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:14:04.156773+00	2025-12-08 18:14:04.156773+00
c1873b43-e68a-4507-82a4-9ba52cc678e8	2	shared	FRIGATE_RTPS_TOMO_USERNAME	\\x66491b4051ea87838d9a01f84daa355d2dbcc4699256597129ef158b201bc110e47d551b9889763031	\N	\N	\N	f	\N	\N	0c2d9e3d-6533-419a-bd02-4830593dadcf	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:14:04.538798+00	2025-12-08 18:14:04.538798+00
d9d578b4-26b2-4a70-a38b-19e7648cc9c9	2	shared	FRIGATE_RTPS_TOMO_USERNAME	\\x5b8fd486d3927c019aa098fa959ebad7f4361a809d05927f1e116c7c2394d302ca992fa65d4a763031	\N	\N	\N	f	\N	\N	5692fef6-09c9-43d8-94df-25c77d145cbd	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:14:05.16137+00	2025-12-08 18:14:05.16137+00
e6f89ba1-b1c0-4510-9bc2-612366b4f3f1	3	shared	FRIGATE_RTPS_USERNAME	\\xb9849e80c4d72333c71ce6dd75ec61e2aaebedb445225bb2bdbedc1905bd0c37ab78c94d47763031	\N	\N	\N	f	\N	\N	ecb331ab-05ef-49e1-99a5-2d0664349759	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:14:17.06696+00	2025-12-08 18:14:17.06696+00
565d5c08-2f10-4fe6-a364-bdd43b0f1fec	3	shared	FRIGATE_RTPS_USERNAME	\\x435e8561d11016a5f882cb25a332e1909782c4cc122dc093c52047f6d6f2284a639e27f5be763031	\N	\N	\N	f	\N	\N	48227d56-f097-4545-af4f-faeb8366f649	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:14:25.311515+00	2025-12-08 18:14:25.311515+00
c8416d7a-ee89-4260-b718-16c883906c82	4	shared	FRIGATE_RTPS_USER	\\x75f998e5b0cae066156d8a5909c5f0d1e08805ce106acc740bba827ad651674dd7eb5c43f7763031	\N	\N	\N	f	\N	\N	377396f2-51fa-4c56-ba55-520968950a40	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:39:54.449627+00	2025-12-08 18:39:54.449627+00
c14ce8af-ff97-4250-b218-c33f0badc492	4	shared	FRIGATE_RTPS_USER	\\x7f43324e16af10524e3b266d2f98602634c481dec9e884b1dd8a4dbb1d144c054dd56422c3763031	\N	\N	\N	f	\N	\N	ecb331ab-05ef-49e1-99a5-2d0664349759	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:39:54.470609+00	2025-12-08 18:39:54.470609+00
79c6d6c2-a968-48ac-9a5b-66b725a594c0	4	shared	FRIGATE_RTPS_USER	\\xf6d44c28c44d769a171e367c41f0899c884765e7ffe3fc35b1807d1e1aa3616d2845f41233763031	\N	\N	\N	f	\N	\N	48227d56-f097-4545-af4f-faeb8366f649	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:39:54.47862+00	2025-12-08 18:39:54.47862+00
b54233b5-9d8a-4f92-a4b1-3a244a3ae148	1	shared	FRIGATE_RTPS_PASSWORD_TOMO	\\x9527f0bc6774fd3a5b4fddaba0d5ecd197cb01382d41a77ed14e703392f4e089763031	\N	\N	\N	f	\N	\N	62d14a21-c3db-4a15-9e7a-b08eb3126629	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:41:13.414558+00	2025-12-08 18:41:13.414558+00
f0bccf2b-1bc2-4ddf-9d45-52946a21692c	5	shared	FRIGATE_RTPS_USER	\\x47297950b8efd07ae4160e00e11bec33d5b41d1afdfa306257c757053b09d600139726829484763031	\N	\N	\N	f	\N	\N	48227d56-f097-4545-af4f-faeb8366f649	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:41:28.173289+00	2025-12-08 18:41:28.173289+00
faf61269-33ac-45d2-a3ce-53dcdd44f399	6	shared	FRIGATE_RTPS_USER	\\xb038f7acd0a7c2deb444dbea3fc2f2e03dcda316f82ad5fca28b26c5f2654eb8804d085065763031	\N	\N	\N	f	\N	\N	ecb331ab-05ef-49e1-99a5-2d0664349759	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:41:55.516624+00	2025-12-08 18:41:55.516624+00
17a4a454-7b0d-4d52-94a0-87250f35b5a1	6	shared	FRIGATE_RTPS_USER	\\x5486534cdceb2e7770d389443c0042456ece0dbd4e81bf2512bb133ead55953c4bf2b5f4f5763031	\N	\N	\N	f	\N	\N	48227d56-f097-4545-af4f-faeb8366f649	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:41:56.175677+00	2025-12-08 18:41:56.175677+00
3020a48b-073f-4d49-873a-426ced18f547	1	shared	FRIGATE_RTPS_PASSWORD_TOMO	\\x52ef4f0f0bbc1fb1c63d1ab5e121fcb03002bf6e429e4c00998dc964020a1aa9763031	\N	\N	\N	f	\N	\N	45d2e9d2-50de-46df-a62d-002bacde0220	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:41:13.37774+00	2025-12-08 18:41:13.37774+00
76c88ea3-2fca-4c0b-a35a-119e17788de3	1	shared	FRIGATE_RTPS_PASSWORD_TOMO	\\xd4836ce9d358bfe4f9d7f79688ba8b12e41ef73949de4f1958771df72a5f128b763031	\N	\N	\N	f	\N	\N	3a5f1d03-a3b9-43ba-9822-727577967d0e	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:41:13.422325+00	2025-12-08 18:41:13.422325+00
9eb9b3ef-7ce5-4a90-ab15-68b26a6d87b9	5	shared	FRIGATE_RTPS_USER	\\x21158de38d0e7ec4bd7d23acc7af37123f33b479f0ac230cb0aa6d9add4b6ccaeb65aab7fad9763031	\N	\N	\N	f	\N	\N	ecb331ab-05ef-49e1-99a5-2d0664349759	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:41:28.154661+00	2025-12-08 18:41:28.154661+00
7d6643ac-c908-438a-99be-d45337888c77	5	shared	FRIGATE_RTPS_USER	\\x8b525d7a6507094d39821f896e384e710701e23ecae9d7ac2be500d20e9d66690fc7be5f7a18763031	\N	\N	\N	f	\N	\N	377396f2-51fa-4c56-ba55-520968950a40	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:41:28.169791+00	2025-12-08 18:41:28.169791+00
c6d872cc-254d-4eb3-be3d-28eb87105d9d	6	shared	FRIGATE_RTPS_USER	\\xdcc3118f37405934007739b4c61a9f2f9844f6621d9b4fc1181b24c11816936404d3b60d16763031	\N	\N	\N	f	\N	\N	377396f2-51fa-4c56-ba55-520968950a40	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:41:55.821764+00	2025-12-08 18:41:55.821764+00
c9e1a973-830e-411f-ac29-277d19290304	1	shared	FRIGATE_RTPS_USER_TOMO	\\xcca59e4afbdf1bb97b1bbcb51a8afb6dbcf8676b872a515ecc2ca41c0d9f2f99593b814bce1a763031	\N	\N	\N	f	\N	\N	1553c8ed-ceb0-427a-a99a-3b1892ea4228	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 18:42:07.081137+00	2025-12-08 18:42:07.081137+00
c2d2fcc1-8c5d-4490-8a8b-1cac7ca419cf	1	shared	FRIGATE_RTPS_USER_TOMO	\\xcc819f40b1a4d8f2371d0f4322016218b0d6b79767268e49b3f7eaac8f82af9ea8d1d7ea2241763031	\N	\N	\N	f	\N	\N	d522fb8a-00c4-4983-b640-453e7db9a6ed	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 18:42:07.099143+00	2025-12-08 18:42:07.099143+00
749acc37-2329-4330-9254-b73ee803f56e	1	shared	FRIGATE_RTPS_USER_TOMO	\\x6df5d400be3dee34cac71e648fc75a3fa2bb19b0bff9a80b14a717729d0bc82a98f457fb8794763031	\N	\N	\N	f	\N	\N	81c12fa8-b20c-4741-b825-377651e5fc2c	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 18:42:07.100926+00	2025-12-08 18:42:07.100926+00
d627eb9a-a643-43aa-8473-3ce70c6d93ab	4	shared	FRIGATE_RTSP_PASSWORD	\\xe62d552c239768ad7864a65880afe4b9bcc504f1c8cab1f19b1db06584dab622b56746b4332ec8763031	\N	\N	\N	f	\N	\N	0b4c3c2f-a2b3-4fa5-bfe4-b04a1120933b	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:16.952243+00	2025-12-08 19:08:16.952243+00
64bb8b9f-bf6a-4b0a-99e6-e2bdf2911b5a	4	shared	FRIGATE_RTSP_PASSWORD	\\x262579b92e71cebe8e8efde7931e9dacc32467dfdb3d70ded4af5e93a8fc48341c76cb2f0b03d0763031	\N	\N	\N	f	\N	\N	0544db56-558c-4290-bdce-b139cae21e6a	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:16.976662+00	2025-12-08 19:08:16.976662+00
535d5be4-58ce-442a-95e4-4d0a1a8221b4	4	shared	FRIGATE_RTSP_PASSWORD	\\xb2d43fd2c04edc7db518a357f854fc9368bff8d6f1a47f17ad4c471bd6e561efd9dc73e20d5855763031	\N	\N	\N	f	\N	\N	82252a1b-031d-47d4-87b2-9466d250a8c9	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:16.989933+00	2025-12-08 19:08:16.989933+00
80a3c7b8-d291-4daa-b6c7-b2b3a3c01da1	2	shared	FRIGATE_RTSP_PASSWORD_TOMO	\\xdd916ce19ea6fa2d37f048424011b0ea324f018e83ae26c65a11e131ee2ae95f763031	\N	\N	\N	f	\N	\N	45d2e9d2-50de-46df-a62d-002bacde0220	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:25.216117+00	2025-12-08 19:08:25.216117+00
725db5ca-8cea-43fd-8194-f7e6dcb25a3a	2	shared	FRIGATE_RTSP_PASSWORD_TOMO	\\x42f9cf01f10294dc44cb4defb503612e9b5240b5c2d2380b92f8a2e9cb754b27763031	\N	\N	\N	f	\N	\N	62d14a21-c3db-4a15-9e7a-b08eb3126629	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:25.226337+00	2025-12-08 19:08:25.226337+00
ffc5c0fe-cc56-479f-b177-b236212b5280	2	shared	FRIGATE_RTSP_PASSWORD_TOMO	\\x874ec46aefac3da2dd6103e6e1ea9c6edecfc8ee004988a1e417a8219f68bafe763031	\N	\N	\N	f	\N	\N	3a5f1d03-a3b9-43ba-9822-727577967d0e	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:25.230399+00	2025-12-08 19:08:25.230399+00
5494bb07-e68f-467f-8311-c746f371d730	2	shared	FRIGATE_RTSP_USER_TOMO	\\xb7637806e56b2521ec2cd65e2afc4a257ebc4e85bce68b45a237dc96803200bde49161029300763031	\N	\N	\N	f	\N	\N	1553c8ed-ceb0-427a-a99a-3b1892ea4228	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:31.699833+00	2025-12-08 19:08:31.699833+00
36a0c9ff-1dea-4a8e-8f0b-0c9891b8b409	2	shared	FRIGATE_RTSP_USER_TOMO	\\x97b1bd3e91ded4f25786d515cf1d5b135af2bbc9d02d5a9c97871e280083765116673522cf91763031	\N	\N	\N	f	\N	\N	81c12fa8-b20c-4741-b825-377651e5fc2c	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:31.730279+00	2025-12-08 19:08:31.730279+00
c4dd691e-8d35-4498-90f8-7641a4dcc1c8	2	shared	FRIGATE_RTSP_USER_TOMO	\\xc54131e992cef7aaad1d13749344fecd7741a87e15b998d2855cf943b6eae4ac3bf9c08e4f11763031	\N	\N	\N	f	\N	\N	d522fb8a-00c4-4983-b640-453e7db9a6ed	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:31.73199+00	2025-12-08 19:08:31.73199+00
1b21a3f8-d3f8-4b3a-868a-3a40b24c4fbd	7	shared	FRIGATE_RTSP_USER	\\x830342c7495bdddb44b4f091eec82f68847e2b3639102399c496ff1a75fa5f42bcb94c42e1763031	\N	\N	\N	f	\N	\N	377396f2-51fa-4c56-ba55-520968950a40	2060d386-1de0-4d43-bb57-ad4833fe317d	\N	2025-12-08 19:08:41.599798+00	2025-12-08 19:08:41.599798+00
0bdc3061-5c21-4402-af22-c65166f963c1	7	shared	FRIGATE_RTSP_USER	\\x1aeecc0241ab78a1fbd2d7db4bf0cbd8f79fb718a7d512d65a974e2c88acca2c9fa4e573b1763031	\N	\N	\N	f	\N	\N	ecb331ab-05ef-49e1-99a5-2d0664349759	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	\N	2025-12-08 19:08:41.618192+00	2025-12-08 19:08:41.618192+00
65c1dfce-4d2b-40b6-9558-72f255d9a323	7	shared	FRIGATE_RTSP_USER	\\x1fa509f4d5d1559b1083418716d0f1fa246bdd641fe92acfc4e5df0a8456bdc9dbf7a71c94763031	\N	\N	\N	f	\N	\N	48227d56-f097-4545-af4f-faeb8366f649	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	\N	2025-12-08 19:08:41.621223+00	2025-12-08 19:08:41.621223+00
266a6184-9cd4-489f-a486-d0463304c90b	1	shared	S3_ACCESS_KEY	\N	\N	\N	\N	f	\N	\N	c7801ab7-06d6-4ab7-8689-9a74d24fb6be	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:48:04.66952+00	2025-12-10 16:48:04.66952+00
d7f7c86a-d066-41f3-a6aa-f7a8eaa66a78	1	shared	S3_ACCESS_KEY	\N	\N	\N	\N	f	\N	\N	1cb18d18-62f3-491b-a38f-149da3258582	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:48:04.68972+00	2025-12-10 16:48:04.68972+00
0bcda03a-a8ec-4b8a-afe6-51edd0bff1a8	1	shared	S3_ACCESS_KEY	\N	\N	\N	\N	f	\N	\N	3f437eb3-cf93-4a6d-ba90-e70a99e71015	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:48:04.69604+00	2025-12-10 16:48:04.69604+00
7f595c63-cdae-45cf-890f-70db55d8a7b7	1	shared	S3_BUCKET	\N	\N	\N	\N	f	\N	\N	3e31f59e-79db-4fde-b1c9-91e0d1796bf2	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:48:15.115873+00	2025-12-10 16:48:15.115873+00
7fbe9247-d309-4dd9-977e-ac7c4a0bb1da	1	shared	S3_BUCKET	\N	\N	\N	\N	f	\N	\N	3d2f056f-8b25-4d64-a955-64b5f40eba1b	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:48:15.122507+00	2025-12-10 16:48:15.122507+00
036235bc-d8c7-496e-a1cc-b868312ad351	1	shared	S3_BUCKET	\N	\N	\N	\N	f	\N	\N	89bddcae-b972-4e07-a4e4-d6bafa879c4c	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:48:15.132753+00	2025-12-10 16:48:15.132753+00
12ba2089-ae4e-49ae-bc04-e3d09c888c70	1	shared	S3_HOST	\N	\N	\N	\N	f	\N	\N	158877fc-94b2-4f3a-a4c1-905aa4a31c82	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:48:41.883074+00	2025-12-10 16:48:41.883074+00
181da39c-f05b-492e-a911-62350fb24c5c	1	shared	S3_HOST	\N	\N	\N	\N	f	\N	\N	a43e7f4b-d339-42e0-8edc-fa3ceb1b1448	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:48:41.883594+00	2025-12-10 16:48:41.883594+00
fa97540a-9bbb-4da5-9f23-754cc9319db4	1	shared	S3_HOST	\N	\N	\N	\N	f	\N	\N	c7b80bc2-ddc2-4978-8101-f3f8812d8fe5	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:48:41.88545+00	2025-12-10 16:48:41.88545+00
e39f6223-5b4e-4818-940a-50a527a53b2a	1	shared	S3_PORT	\N	\N	\N	\N	f	\N	\N	3656a0c4-d7aa-406c-abe7-4f59a9d91d5b	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:48:51.236674+00	2025-12-10 16:48:51.236674+00
5f07e592-8558-4ffc-aa74-488b3aaac5dd	1	shared	S3_PORT	\N	\N	\N	\N	f	\N	\N	ea81c8b4-8167-4066-8274-7ee811a3f2b3	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:48:51.240533+00	2025-12-10 16:48:51.240533+00
89b1ad59-364f-4325-9c4b-81005dfdb883	1	shared	S3_PORT	\N	\N	\N	\N	f	\N	\N	2f685321-31db-4dc3-8884-a12a60064b3d	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:48:51.245139+00	2025-12-10 16:48:51.245139+00
ae7ccb0e-4f73-4236-a69a-075ae99b1de7	1	shared	S3_SECRET_KEY	\N	\N	\N	\N	f	\N	\N	afc23972-1748-45c5-9a31-8732b095a451	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:03.468365+00	2025-12-10 16:49:03.468365+00
28de0554-fd24-4bd4-b056-2000640e9b1c	1	shared	S3_SECRET_KEY	\N	\N	\N	\N	f	\N	\N	e07ac864-e5eb-4735-9b51-19053524df41	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:49:03.468945+00	2025-12-10 16:49:03.468945+00
18063347-1b0e-4b21-b458-15c32b0bf751	1	shared	S3_SECRET_KEY	\N	\N	\N	\N	f	\N	\N	5c3e9799-4dbf-4125-8ed0-e4cc2fc43a5c	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:49:03.477788+00	2025-12-10 16:49:03.477788+00
76440291-a906-49bf-916e-e5330f8e8d67	2	shared	S3_PORT	\\x076958bda0d0f3c80b0725434361a2cc707b6d5376548502363eba7bf83c1c763031	\N	\N	\N	f	\N	\N	ea81c8b4-8167-4066-8274-7ee811a3f2b3	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:49:13.062469+00	2025-12-10 16:49:13.062469+00
1b1156ea-f6d5-43cd-9ce2-ab00d275276d	2	shared	S3_PORT	\\x01743213e5684ec1450a6e541a19eec5c3fe754586d5e505b9b747135e9ce0763031	\N	\N	\N	f	\N	\N	3656a0c4-d7aa-406c-abe7-4f59a9d91d5b	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:49:13.50959+00	2025-12-10 16:49:13.50959+00
62b816aa-e8cc-4a94-9679-40dc3d7872ea	2	shared	S3_PORT	\\xcef4c836e4d4967095f585a256db7d9897ed3ec79b2a01568f47616ff55b86763031	\N	\N	\N	f	\N	\N	2f685321-31db-4dc3-8884-a12a60064b3d	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:13.985117+00	2025-12-10 16:49:13.985117+00
5f8dc89d-0bc0-4438-8c97-af406ff9a8df	2	shared	S3_SECRET_KEY	\\x77a2478ff9674ed6f6e7c88e1c8d33b8259fb6e6bedbc749b82f64a42bbf7d3f42112d538c61f26a2ecf3e19883d07917cec546de585619ae9d1a60521cd0d41dd56ad5c763031	\N	\N	\N	f	\N	\N	afc23972-1748-45c5-9a31-8732b095a451	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:28.66202+00	2025-12-10 16:49:28.66202+00
8781578c-e06a-4009-8fff-fc7584745524	2	shared	S3_HOST	\\x80d3c91cf8dd4a1568d95dd2490c2b7937880bd1ead5bd09c65f8590de73dd28c010989c83923314c0abba2fba6207763031	\N	\N	\N	f	\N	\N	158877fc-94b2-4f3a-a4c1-905aa4a31c82	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:49:45.201677+00	2025-12-10 16:49:45.201677+00
8b846178-5530-4e93-97ed-c3008438e5aa	2	shared	S3_HOST	\\xb416d4727932340b42220f6116078f72254c39d3bf9e6f66bc326ba6bfd3c78343279479332da8210d29dcec32a9e2763031	\N	\N	\N	f	\N	\N	c7b80bc2-ddc2-4978-8101-f3f8812d8fe5	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:49:45.96292+00	2025-12-10 16:49:45.96292+00
5739a7d7-2efb-4572-83d6-0ba02ca5e5f3	2	shared	S3_HOST	\\x4e96718779c0d1b0233ba4fff7f659ed3ba57ed093cc78263d81dfb8c8baac02376797acd64d170cbe556c8d1b81d6763031	\N	\N	\N	f	\N	\N	a43e7f4b-d339-42e0-8edc-fa3ceb1b1448	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:49:46.684061+00	2025-12-10 16:49:46.684061+00
4b230f43-4355-44e8-9b21-47e5d0cd055b	2	shared	S3_ACCESS_KEY	\\xbffd65d65e3c87bbbe16004ea21a05ab3580bf56a078ee809647ad7930e86d0ea170d5694cd3bff6c818bb3bd364185d763031	\N	\N	\N	f	\N	\N	c7801ab7-06d6-4ab7-8689-9a74d24fb6be	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:50:02.162084+00	2025-12-10 16:50:02.162084+00
062227e3-a61f-4acf-8799-0afc8423d095	3	shared	S3_HOST	\\x80d3c91cf8dd4a1568d95dd2490c2b7937880bd1ead5bd09c65f8590de73dd28c010989c83923314c0abba2fba6207763031	\N	\N	\N	f	\N	\N	158877fc-94b2-4f3a-a4c1-905aa4a31c82	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 16:50:12.826913+00	2025-12-10 16:50:12.826913+00
846f2df7-caef-4a9a-adc8-218001827c98	3	shared	S3_HOST	\\xb416d4727932340b42220f6116078f72254c39d3bf9e6f66bc326ba6bfd3c78343279479332da8210d29dcec32a9e2763031	\N	\N	\N	f	\N	\N	c7b80bc2-ddc2-4978-8101-f3f8812d8fe5	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 16:50:13.309292+00	2025-12-10 16:50:13.309292+00
0a71e8da-7f00-4798-b5d6-65d062f68db3	2	shared	S3_BUCKET	\\x75392cc53e8bc7b048bb9453a0cbe4d512483b54b87b9e5f952294edc9731c8463806585c0e337d28b20cf60e1f7e8763031	\N	\N	\N	f	\N	\N	3d2f056f-8b25-4d64-a955-64b5f40eba1b	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 16:50:36.975406+00	2025-12-10 16:50:36.975406+00
e0b7ea4c-009e-4bb3-b6b6-30d5d5f73712	1	shared	ACCESS_KEY	\N	\N	\N	\N	f	\N	\N	d5c29797-6578-4b33-8814-ee45e548ca79	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:00.589441+00	2025-12-10 16:52:00.589441+00
2537afee-2beb-4c19-89af-7ac073c1d91a	1	shared	ACCESS_KEY	\N	\N	\N	\N	f	\N	\N	ea87e63f-ac44-4598-8e60-febf81835139	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:00.592065+00	2025-12-10 16:52:00.592065+00
e60f217c-f365-419a-aa14-fbb1d6bde4c2	1	shared	ACCESS_KEY	\N	\N	\N	\N	f	\N	\N	98bb7e4a-3abd-445c-81c2-1d405a19eaaa	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:00.593339+00	2025-12-10 16:52:00.593339+00
508e9ed4-37e9-4993-899d-a8e8d7b9a7cd	1	shared	MINIO_DOMAIN	\N	\N	\N	\N	f	\N	\N	cece50ee-4245-4c5f-a407-58970814ecd9	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:08.193094+00	2025-12-10 16:52:08.193094+00
085c85c4-5455-49d8-876c-ee3a74d6d505	1	shared	MINIO_DOMAIN	\N	\N	\N	\N	f	\N	\N	1580bd8c-6db6-4f7b-9610-b8e51c23d301	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:08.240495+00	2025-12-10 16:52:08.240495+00
baa5eb1f-90f5-4257-b0e4-9ec8e6ce5fdc	1	shared	MINIO_DOMAIN	\N	\N	\N	\N	f	\N	\N	f62ce38b-53ba-45ef-9663-e4fb369b7865	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:08.247305+00	2025-12-10 16:52:08.247305+00
a9250f39-ec12-4f79-9bfc-89b63f6a5748	1	shared	MINIO_PORT	\N	\N	\N	\N	f	\N	\N	e1feb93a-7336-45f4-bba3-b0e866107799	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:14.752662+00	2025-12-10 16:52:14.752662+00
4d106f8b-5fa9-497e-bc2e-7439e78c12a1	1	shared	SECRET_KEY	\N	\N	\N	\N	f	\N	\N	3144cb46-7bd1-4d6d-ad13-41134a18bccc	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:37.690513+00	2025-12-10 16:52:37.690513+00
812d243e-9063-4b61-8616-67904ceeb1fb	2	shared	MINIO_ROOT_PASSWORD	\\x8a4db9c0310c735d148b24ce4ecd1a468f03f8c69385be9a0e02ceecdb2a36810bc662a2763031	\N	\N	\N	f	\N	\N	1ccc79cf-7ac5-4712-a0fe-bb50306ff6b6	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:53:54.385035+00	2025-12-10 16:53:54.385035+00
44e2ca6d-bede-4487-a240-c4fc5aa2266a	1	shared	MINIO_PORT	\N	\N	\N	\N	f	\N	\N	65cafe79-890c-4fe0-b4c5-8a8019a8d8bd	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:14.753623+00	2025-12-10 16:52:14.753623+00
b83163fb-8646-45a0-b83e-2b387e4fc7c7	1	shared	MINIO_ROOT_PASSWORD	\N	\N	\N	\N	f	\N	\N	1ccc79cf-7ac5-4712-a0fe-bb50306ff6b6	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:22.55335+00	2025-12-10 16:52:22.55335+00
e97bcd67-08b3-41df-a7db-9193d32e85f7	1	shared	MINIO_ROOT_USER	\N	\N	\N	\N	f	\N	\N	bcabc74c-544f-47d6-9048-74b2267044d4	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:28.827289+00	2025-12-10 16:52:28.827289+00
e5a8234a-2ad8-4a4b-9e55-fe99b4be6fb7	1	shared	MINIO_ROOT_PASSWORD	\N	\N	\N	\N	f	\N	\N	defbb33b-11a9-4023-afe0-581e24be3824	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:22.526357+00	2025-12-10 16:52:22.526357+00
75225cd3-a6a0-4188-a087-6f62f2438f21	1	shared	MINIO_ROOT_PASSWORD	\N	\N	\N	\N	f	\N	\N	7d889cef-90b5-42ea-8fbc-519b35aa9849	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:22.552497+00	2025-12-10 16:52:22.552497+00
baaad99a-3c3d-4a47-a089-329d457461b8	1	shared	MINIO_ROOT_USER	\N	\N	\N	\N	f	\N	\N	5347e33a-f145-4d87-bb23-2778aeec61b0	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:28.829934+00	2025-12-10 16:52:28.829934+00
4a8081b9-fe3d-48e3-9e70-04d1fb92cd44	1	shared	SECRET_KEY	\N	\N	\N	\N	f	\N	\N	401c36a6-fa1f-421a-9cf4-b474dd3e2a5e	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:37.689716+00	2025-12-10 16:52:37.689716+00
b3aa07c1-7026-4efc-ad63-ebf646491383	2	shared	MINIO_DOMAIN	\\xdddc0f07272439f6884e17d94fbdb3ec730e549cdaf52cc630c5e55fdb34bd56140122c63d158fc072cd9572622fa3763031	\N	\N	\N	f	\N	\N	f62ce38b-53ba-45ef-9663-e4fb369b7865	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:52:58.02922+00	2025-12-10 16:52:58.02922+00
3fcb535d-b307-4f13-b04d-28565c934215	2	shared	MINIO_PORT	\\x0b785b719476b36c6126bace1e9d4d18c4a68e627b5b7cb8ef74c7cea05772fd763031	\N	\N	\N	f	\N	\N	e1feb93a-7336-45f4-bba3-b0e866107799	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:53:10.393744+00	2025-12-10 16:53:10.393744+00
3c37a771-a3fc-4e48-a653-cad97d644ae8	2	shared	MINIO_PORT	\\xdd45581d8919bb9285263ef49331406c677ca6fd712f2e72fe29775140579581763031	\N	\N	\N	f	\N	\N	53c329b8-0679-487e-8838-ccb31460911b	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:53:11.163002+00	2025-12-10 16:53:11.163002+00
5b61ccba-92ce-4b63-a213-9bf8e2065217	2	shared	MINIO_PORT	\\x6c19d8eafda0f8106e9936bbce80ee7020c18cfef4f1dbafb323ebb7f42c4cf3763031	\N	\N	\N	f	\N	\N	65cafe79-890c-4fe0-b4c5-8a8019a8d8bd	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:53:11.612794+00	2025-12-10 16:53:11.612794+00
733de489-0836-4d59-ac47-0c82344d3c1f	2	shared	ACCESS_KEY	\\x6bef0968feac81941426ec2cbafc690eb8e9402e99848c98e366fd57fa0b7271a4402d83763031	\N	\N	\N	f	\N	\N	ea87e63f-ac44-4598-8e60-febf81835139	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:53:26.417594+00	2025-12-10 16:53:26.417594+00
0acc4a3f-ed6b-464b-b6be-4b0038eb0868	2	shared	MINIO_ROOT_PASSWORD	\\xdac523130b36380613ea79f954156991d10da644dd18b366e9a6014c50ea001e818fdc587d2be21e763031	\N	\N	\N	f	\N	\N	7d889cef-90b5-42ea-8fbc-519b35aa9849	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:53:55.307558+00	2025-12-10 16:53:55.307558+00
b311ef39-43ad-4f53-9883-bdf1f942ace4	2	shared	MINIO_ROOT_USER	\\xf4ce2c1fda46982cfc0a864667b5c8a27f7d38a8fb05c3c61364773c80f13a4c17763031	\N	\N	\N	f	\N	\N	bcabc74c-544f-47d6-9048-74b2267044d4	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:54:09.613495+00	2025-12-10 16:54:09.613495+00
6dd8d52d-0e35-4fbc-9f20-4831d8b8dc56	2	shared	MINIO_ROOT_USER	\\x907417d7605741ef748ac06df000c3c98e2de87ab1dc763e05bcd5ce60da6d5aee763031	\N	\N	\N	f	\N	\N	4d5042f0-67c4-43b0-8619-0bda5a6eb3dc	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:54:10.126848+00	2025-12-10 16:54:10.126848+00
7ccbf85d-5fff-454f-974a-32319f6d2d7d	2	shared	MINIO_ROOT_USER	\\xc86ee89fe57998df19454fcd17f1693eeeea0ead26b6b807b919be40f6254459e2763031	\N	\N	\N	f	\N	\N	5347e33a-f145-4d87-bb23-2778aeec61b0	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:54:10.582774+00	2025-12-10 16:54:10.582774+00
a6d74d18-9a03-4141-a8bf-80848754bec0	2	shared	SECRET_KEY	\\x2797196039595ed7291b8bc42a1eefaf5bf0cd494d289308792e708f50481faf7367b87f763031	\N	\N	\N	f	\N	\N	46f68df2-6d5e-4d76-8264-71368a448144	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:54:24.083945+00	2025-12-10 16:54:24.083945+00
c49c881f-d36e-41b1-992a-b60ef35b2834	1	shared	MINIO_ROOT_USER	\N	\N	\N	\N	f	\N	\N	4d5042f0-67c4-43b0-8619-0bda5a6eb3dc	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:28.810843+00	2025-12-10 16:52:28.810843+00
ea46f87b-e248-4c3b-a893-7febe2c96f21	1	shared	SECRET_KEY	\N	\N	\N	\N	f	\N	\N	46f68df2-6d5e-4d76-8264-71368a448144	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:52:37.668892+00	2025-12-10 16:52:37.668892+00
bd243c4e-d927-438b-a355-9f93290bdebc	2	shared	MINIO_DOMAIN	\\x40aed96b3242944e1db95f43a301fc81e1c349292869a323b35acca4d1892add02c07da1bb763031	\N	\N	\N	f	\N	\N	1580bd8c-6db6-4f7b-9610-b8e51c23d301	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:52:57.341655+00	2025-12-10 16:52:57.341655+00
f4f87859-83e2-49b7-b9f3-7d2b698bf1da	2	shared	ACCESS_KEY	\\x20cf3726d7f13f4b042dc0c260cd8499b62b3ada9f5b2439a65cf7e091c82c8c5c763031	\N	\N	\N	f	\N	\N	d5c29797-6578-4b33-8814-ee45e548ca79	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:53:27.079614+00	2025-12-10 16:53:27.079614+00
228dee0e-30a5-4f47-b69b-98a1891c3eea	2	shared	MINIO_ROOT_PASSWORD	\\x35992604a4bf89195baeeb6669762840b292a9430b7365db52cc445a8f621aaa774cbbb0763031	\N	\N	\N	f	\N	\N	defbb33b-11a9-4023-afe0-581e24be3824	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 16:53:54.892298+00	2025-12-10 16:53:54.892298+00
60fdb01d-3d08-4d79-81d2-d069c9a711ec	2	shared	SECRET_KEY	\\xa038dd32928afdcda6ce427d86d68bae0e7f8a6d3028ace7b911bc95b4b286997e6cdcc1763031	\N	\N	\N	f	\N	\N	401c36a6-fa1f-421a-9cf4-b474dd3e2a5e	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 16:54:23.425468+00	2025-12-10 16:54:23.425468+00
f2d748f8-44cc-4a61-8cb6-fa2af3bb4b1b	2	shared	SECRET_KEY	\\x17a811d2fce2da35b1d0536f601892ffd23af93e5d6af3db35be9ac8817f4d569fba038a6ac6fee8763031	\N	\N	\N	f	\N	\N	3144cb46-7bd1-4d6d-ad13-41134a18bccc	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 16:54:26.219476+00	2025-12-10 16:54:26.219476+00
14a676d1-bad9-4ec8-a646-f2201b7ae675	2	shared	ACCESS_KEY	\\x7536bbe53c5db6e0b9fcc36dc663d0a7fcbff24326fc97a3c86b959791c61fd7aa763031	\N	\N	\N	f	\N	\N	98bb7e4a-3abd-445c-81c2-1d405a19eaaa	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 17:03:42.14792+00	2025-12-10 17:03:42.14792+00
3b3f78a8-2e0f-4c52-90a3-66ba42fadb1c	2	shared	S3_ACCESS_KEY	\\x72af34e0bda796d49b53d45d26bdb56cc08808d2b78366c879bcb44c8782990366763031	\N	\N	\N	f	\N	\N	1cb18d18-62f3-491b-a38f-149da3258582	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 17:03:47.569409+00	2025-12-10 17:03:47.569409+00
606aeb70-e94c-4b92-9685-b082d8554fdd	2	shared	S3_ACCESS_KEY	\\x5ba6c659e2e649a82dbfddf9132d7adae1a38b0ab3a4a3318fafe6a46ff9973c6e763031	\N	\N	\N	f	\N	\N	3f437eb3-cf93-4a6d-ba90-e70a99e71015	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 17:03:48.250363+00	2025-12-10 17:03:48.250363+00
a2a57311-abc8-4f99-96ff-53c140a26019	2	shared	S3_SECRET_KEY	\\x4901e35f496df70f3bbfc1e24e9a79352628fc132c39bb38d31c3fc2ad66dfd4d6f62516763031	\N	\N	\N	f	\N	\N	e07ac864-e5eb-4735-9b51-19053524df41	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 17:03:58.886119+00	2025-12-10 17:03:58.886119+00
2f1f1ae5-0f83-4215-aea1-d6ca4846fca8	2	shared	S3_SECRET_KEY	\\x5548e8f99a32e2bc5e79cdb952a8b0acc842d174117739722d51536caed70ed6ff5d8d81763031	\N	\N	\N	f	\N	\N	5c3e9799-4dbf-4125-8ed0-e4cc2fc43a5c	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 17:03:59.504337+00	2025-12-10 17:03:59.504337+00
1001d4bf-1e79-4da7-8f73-ce94cad191e9	2	shared	S3_BUCKET_LOKI	\N	\N	\N	\N	f	\N	\N	3e31f59e-79db-4fde-b1c9-91e0d1796bf2	46346785-4314-4bd6-928f-e09d54847e98	\N	2025-12-10 17:04:34.093493+00	2025-12-10 17:04:34.093493+00
5685679b-900b-4527-aa76-16a326be111c	3	shared	S3_BUCKET_LOKI	\\xa104c7194b99284a3bd7e2a1c5e083ad98ae1bcf17cdbc9258e7be0e7011d729ddd0334aa15f208ed87f0edfeb7d8a763031	\N	\N	\N	f	\N	\N	3d2f056f-8b25-4d64-a955-64b5f40eba1b	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 17:04:34.109991+00	2025-12-10 17:04:34.109991+00
f46bc22d-9563-479e-ae43-25eed72a5a13	2	shared	S3_BUCKET_LOKI	\N	\N	\N	\N	f	\N	\N	89bddcae-b972-4e07-a4e4-d6bafa879c4c	ed0fa5be-f07b-4aeb-bddb-5068d048c889	\N	2025-12-10 17:04:34.116454+00	2025-12-10 17:04:34.116454+00
9870109f-b5ec-4896-90b1-a60b20000c09	3	shared	MINIO_ACCESS_KEY	\\x6e04d1d4c965ad4aa9d4300355a9ae4ad825084ad0a45f9dfff7364cd840f9d5c6763031	\N	\N	\N	f	\N	\N	98bb7e4a-3abd-445c-81c2-1d405a19eaaa	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 17:08:55.906632+00	2025-12-10 17:08:55.906632+00
353ef5c9-aaa1-404b-98a0-cbb0fa7208cd	3	shared	MINIO_ACCESS_KEY	\\xe7858bb49690f6115558d0ceef1104df2eb971dfc7c8c39eaae80bcd2e005907e7a2dea6763031	\N	\N	\N	f	\N	\N	ea87e63f-ac44-4598-8e60-febf81835139	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 17:08:55.91174+00	2025-12-10 17:08:55.91174+00
9850e218-e48e-438d-b9e2-a997af619559	3	shared	MINIO_ACCESS_KEY	\\x2a4e6973315b49cc70b22b44b6a7492766ebc6de433f215ef17caa34f08e65b154763031	\N	\N	\N	f	\N	\N	d5c29797-6578-4b33-8814-ee45e548ca79	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 17:08:55.91256+00	2025-12-10 17:08:55.91256+00
8a16c28c-79b3-49ee-8650-f1c702cb7a06	3	shared	MINIO_SECRET_KEY	\\xd940229ef1457b4930c4bb8c327ca30d06f9138fafe223a9930bbdfe32580705d6e822c5763031	\N	\N	\N	f	\N	\N	401c36a6-fa1f-421a-9cf4-b474dd3e2a5e	df55f1e8-12b3-436c-84b4-270f7a54c1c2	\N	2025-12-10 17:09:06.094908+00	2025-12-10 17:09:06.094908+00
a3a5c225-c57c-4f06-8995-7ffce5ab5672	3	shared	MINIO_SECRET_KEY	\\x23afe5033097a1951521b21e131bd20d2afbe96e144e7ce958ab94fb61aa03c4de6289e1d368698a763031	\N	\N	\N	f	\N	\N	3144cb46-7bd1-4d6d-ad13-41134a18bccc	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	\N	2025-12-10 17:09:06.095527+00	2025-12-10 17:09:06.095527+00
21a8c294-572f-4db7-9333-7514acb78a92	3	shared	MINIO_SECRET_KEY	\\xa8212a574b8c71dc8cf95fa856fd0628d38cf5b7e4df279063b81e9d69c026e62a158a6a763031	\N	\N	\N	f	\N	\N	46f68df2-6d5e-4d76-8264-71368a448144	94e67651-7c8f-4de7-b648-f9632e94ed99	\N	2025-12-10 17:09:06.107528+00	2025-12-10 17:09:06.107528+00
4c9f189b-a492-4249-a1e7-0f1a8c1d9eaf	3	shared	S3_SECRET_KEY	\\x2dd60f1f218353db4eb0a9c998f72ed107d020540135f54720ed87478cd04a41b90c4c163be30e6d0218bc6a63be52e2e8ae3b8647b3ac5e407ceae94d71a4a22471783e763031	\N	\N	\N	f	\N	\N	afc23972-1748-45c5-9a31-8732b095a451	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 17:27:22.363817+00	2025-12-10 17:27:22.363817+00
853c23fc-1570-4915-be51-7036c4fa7900	3	shared	S3_ACCESS_KEY	\\x83669335d7bf3315764e39330a3f96613165963cb7d63e9a5a9b3069f7dddc841220d4eca2ac40f3bd6c9ec2c77ff092763031	\N	\N	\N	f	\N	\N	c7801ab7-06d6-4ab7-8689-9a74d24fb6be	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	\N	2025-12-10 17:27:23.809885+00	2025-12-10 17:27:23.809885+00
89a88a0a-83f4-45ad-82a5-b18bb485d923	1	shared	CLOUDFARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	69acfb44-8f7c-4caf-afa0-008179f9640d	73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	\N	2025-12-16 21:19:27.765223+00	2025-12-16 21:19:27.765223+00
0cc0b055-a162-4db6-87d6-fbf33cf8a582	1	shared	CLOUDFARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	0e9594fa-cd11-4a9e-b31f-81a436b44bc2	dca4e684-c441-41fa-91d1-986fcbbf14c1	\N	2025-12-16 21:19:27.773564+00	2025-12-16 21:19:27.773564+00
d708872d-4388-413b-8d26-34dec7c03330	1	shared	CLOUDFARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	834d1c2a-5342-48ee-b341-54d2d83bac7b	46b4244c-c2ce-45ec-891f-7dd38d86e753	\N	2025-12-16 21:19:27.77441+00	2025-12-16 21:19:27.77441+00
b6ef26e2-6a25-45b8-8e76-04ca9bafce82	2	shared	CLOUDFLARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	834d1c2a-5342-48ee-b341-54d2d83bac7b	46b4244c-c2ce-45ec-891f-7dd38d86e753	\N	2025-12-16 21:19:57.889901+00	2025-12-16 21:19:57.889901+00
d086629c-cfe2-483e-9eac-6c7e85e6fc0f	2	shared	CLOUDFLARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	0e9594fa-cd11-4a9e-b31f-81a436b44bc2	dca4e684-c441-41fa-91d1-986fcbbf14c1	\N	2025-12-16 21:19:57.911829+00	2025-12-16 21:19:57.911829+00
ccb8518e-92b7-467f-8800-4fd0947ccf12	2	shared	CLOUDFLARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	69acfb44-8f7c-4caf-afa0-008179f9640d	73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	\N	2025-12-16 21:19:57.912744+00	2025-12-16 21:19:57.912744+00
e57d2714-4847-43a5-b278-7105a36920d6	3	shared	CLOUDFLARE_TUNNEL_TOKEN	\\x07ef7df91a9c77bad6e3e60d459fab74e7f902aeb5031a4e062a6e88d1f88034e69f66a75a60b1f413ab4495cf73840964f98ea1625c4206bbd72f9abb2e23e9370946023c9b0099d7964d2590d2d878676ca704343b12091e3ce421f6d9a0a2c942ddfa68ae02e5d80c464e2c596e7b37bcd559b376b7409eddc6afec8fecb0edcf41999e9aab4feec1bc8e9adc52bd204516322a7f640e880f869f6ea10013e6d7a32f4feb8aab1fdea1a7c5716bce378376c0a195a18bce6a33712e23269944c2bf95a0186fbcf5461f6133f26574e9ca73c6763031	\N	\N	\N	f	\N	\N	69acfb44-8f7c-4caf-afa0-008179f9640d	73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	\N	2025-12-16 21:29:01.644212+00	2025-12-16 21:29:01.644212+00
\.


--
-- Data for Name: secrets; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secrets (id, version, type, "secretBlindIndex", "secretKeyCiphertext", "secretKeyIV", "secretKeyTag", "secretValueCiphertext", "secretValueIV", "secretValueTag", "secretCommentCiphertext", "secretCommentIV", "secretCommentTag", "secretReminderNote", "secretReminderRepeatDays", "skipMultilineEncoding", algorithm, "keyEncoding", metadata, "userId", "folderId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: secrets_v2; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.secrets_v2 (id, version, type, key, "encryptedValue", "encryptedComment", "reminderNote", "reminderRepeatDays", "skipMultilineEncoding", metadata, "userId", "folderId", "createdAt", "updatedAt") FROM stdin;
0fb46e27-45ae-4a28-b7c0-be8e0620d6a6	1	shared	GHCR_EMAIL	\\xc3ae7570cba93cd0e973385f5a0559bdc98d4c58918f0b1b5d9add4ab59823e561dd51f8c6699992b4c8121d3b1061e25dbc4fd45433b6763031	\N	\N	\N	f	\N	\N	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
4a9782bc-5cb2-4d34-8618-9a5d6cf021ef	1	shared	GHCR_SERVER	\\x68c1de569ac1287afc134f11096281850881272b0e7d1f46011a7e9bfe0c23dc3c729f464ed7794ebe7292763031	\N	\N	\N	f	\N	\N	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
5e7d1da6-c4d5-4527-bcb4-3e9619777891	1	shared	GHCR_TOKEN	\\x0d618f9d03074872bfd2224efd01257949e849e51be491e14dde4edbc3eba60c74aa8641bd7efc3bf84bc0adfd050a9380b6ead618f3dd77785eec7f25fe403a77dd4242763031	\N	\N	\N	f	\N	\N	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
6feade35-dedd-4a52-9bcc-f0dacb29f93c	1	shared	GHCR_USERNAME	\\x5352b34166c48e1dcf8d175a22244bcd6f263d0a2cab909e3bad396f4ca64d21538fed650ef6208c83763031	\N	\N	\N	f	\N	\N	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
955131a7-4aff-4cb2-bf7a-4b09988a47f1	1	shared	JWT_SECRET	\\x6712f4f20135c3321ba26a04f8ad5ba705d98efab960aa5fd6cf1ae8564359290759fc55763031	\N	\N	\N	f	\N	\N	b3008a94-6937-43e8-ad16-74c17e9c18d5	2025-10-22 15:38:23.43611+00	2025-10-22 15:38:23.43611+00
9eeb7e40-2160-4c2f-b904-3f222d13b3fd	1	shared	GHCR_EMAIL	\\x506c3bb88f631a405dff5779d8ac84b266765c31aeece144da40225452c20c5103979c476595a12093cd973428c2ce9bba3320173fcbf3763031	\N	\N	\N	f	\N	\N	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
6d1de7da-26b0-424a-a8d1-50492f6defd2	1	shared	GHCR_SERVER	\\x1f5f42f4e9738ae08c4d8fdd5885ca3085f594ce3fa7cd56b2dc9020fac7a56f6d70212e0d3170994e4df9763031	\N	\N	\N	f	\N	\N	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
d73c53f9-7323-44ad-982a-d5bc35bae734	1	shared	GHCR_TOKEN	\\xa5871e1244ca5f7c2625f1e0b7f840e594bfa6fa984b00dc61946e344befc61094ed2e2299b4b3136d80654ba5571debba8ee50487c012bdcd603ebb4bf6b8c5f0b77f50763031	\N	\N	\N	f	\N	\N	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
d3744560-8bda-4b87-bf9e-f75392aa538a	1	shared	GHCR_USERNAME	\\xfd3a00e9dc3ec61ff7f6fc4630f44a97c03c630c54803b0a84afe342868615c9663f666aba0972f87f763031	\N	\N	\N	f	\N	\N	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
236c32a1-156e-4252-968c-b60106a0d690	1	shared	JWT_SECRET	\\xb09b9e7ff6b41f362401c9900c451db15f30003ca91452c38ce1f6dffb3c3b4ee906fc02763031	\N	\N	\N	f	\N	\N	9a38b5d6-0b73-4e67-87b6-a80561ace832	2025-10-22 15:38:58.192694+00	2025-10-22 15:38:58.192694+00
8a6801ca-cc08-46cd-aade-76eefb8b1070	1	shared	GHCR_EMAIL	\\x49ed90c7d7cf6d674ac11aa9246b0b306b07e3b5afd6881bcd60a13ac9a4d581e7ffd48e3002cda996998ed260d513b5f89ebc31ab2468763031	\N	\N	\N	f	\N	\N	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
3fe2381d-dc02-4610-840f-dc4d151d7ccc	1	shared	GHCR_SERVER	\\x82e0128e1d72fc22bc810fb569d8712b9321cc57ad78918239c42fe7fcee2fe6cfeadcd5b37fbf79bcb397763031	\N	\N	\N	f	\N	\N	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
c02f0f6e-2af2-4615-bee6-5c62c87c17e8	1	shared	GHCR_TOKEN	\\x74e588fae0e23fed44f68c16d823bf2a9fbea681f043ba448a5fa0ffae7497f4f2e7af75b7db3e09d2ee2c6fe156b9cb37af6e96b5a212b48b085599a9b4d0f22ccf4ad4763031	\N	\N	\N	f	\N	\N	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
d32b6dbf-a8fd-46e9-9f69-345e1057de63	1	shared	GHCR_USERNAME	\\xc80770f8b9f108e9143c2d86da1e0e014e4a00c46e1d61c0d137e59e5e358a7ca96c14e8e67fc7a057763031	\N	\N	\N	f	\N	\N	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
72d68472-0a14-4e05-b2fc-ed32a35449d1	1	shared	JWT_SECRET	\\x522c1ac08e465dd905079ba705200038d4485aba48c7de73c6ac5124f911374f267d3cca763031	\N	\N	\N	f	\N	\N	ee4196e1-ca5d-48d0-8dff-35475654cf98	2025-10-22 15:39:15.756348+00	2025-10-22 15:39:15.756348+00
481b6e57-9fa1-4dcd-9679-41ee6e5cf48e	1	shared	ENVIRONMENT	\\xc281cba11e55164619a6b2f6e32c3394ff9b66279d69275dc3873ec7decbd0763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
9bf0209c-51df-4095-b4fb-d733c017df21	1	shared	HSM_DB_ORACLE_DB	\\x93e197f421ac5f3f89ebbb9df02facaf50993040e4e7a3f5934cf33a1d0860fcd70a763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
807d08b0-f74f-4c19-b371-cfab736241f7	1	shared	HSM_DB_ORACLE_HOST	\\xc503e4d445274b181b09d1d41cfd5aab06d70b5a55c03b026054e530d76021361a25a540a4763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
fcb487d3-211f-4a63-9c4f-58e1be30a685	1	shared	HSM_DB_ORACLE_PASSWORD	\\x6786920de013f248245dae218c4526ccb22e1e4d780837ae7bf61678b1264c489ce6fc300c763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
ff8d64c0-d88f-44da-a2d4-63f6b076daf7	1	shared	HSM_DB_ORACLE_PORT	\\x656c500ff2266ebd00614a83e9d621f65814079fd6bce97a4a07d932a8a9006c763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
ed803480-6840-4d6a-a1c6-18fbda891cd7	1	shared	HSM_DB_ORACLE_USER	\\xedc3bf8346e01633db62f562ee53b61af9bbc8f76c2f97a88f63e31b5584f4763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
2d5ee3d1-622c-447a-9b6c-f4786b8ab8f7	1	shared	HSM_DB_POSTGRES_DB	\\x3902ad18d233314c61179f3a08fddb060e020c67746db313ab59a5866ed153763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
c3ff5e7c-5bfa-4863-aa35-0deb60fc8ad9	1	shared	HSM_DB_POSTGRES_HOST	\\x0a8553d6b861391f8db8c082a19e69bf8e7a79bf6f0d2b5aaaf618601c94d986e1ab25e909130b0d3f1749d1122de4763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
74e596c7-cc37-479f-bc96-b5ead5c9fe6c	1	shared	HSM_DB_POSTGRES_PASSWORD	\\xa298626950385baafb919445c2479a04cac2f9f0d04a9e03233687f317d9ed9dbda3ff3a763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
c99fbc68-943b-458d-9580-6de5c882ef8e	1	shared	HSM_DB_POSTGRES_PORT	\\xdfa2709858b8116761f2d7492a76923003765097eac5e708a99519147a1f946d763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
301ab46c-777d-455b-891f-932069619684	1	shared	HSM_DB_POSTGRES_USER	\\x0d1018a518c0d7830c10c3f61bc392dbc7f63e92d56abdc5a3724a07b9ef776b293db658763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
205e844b-fabc-480d-9af1-d8cdd33fcf67	1	shared	HSM_DB_REDIS_HOST	\\xf681824108f4c86f74a21ae0268cac8f0a69ea206d9d5150b907d030c46920d318fe396aeaa0904bc8842b9b763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
c7f8d8cd-bc7d-46c2-bbd0-27d0921d0121	1	shared	HSM_DB_REDIS_PASSWORD	\\xb8b9f9b5b79068b00e85a55f5a59f078e33bbe26102eda4e2439003d9d063256d1763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
856f01e6-9812-4e19-a058-5c6b3b0e1a6d	1	shared	HSM_DB_REDIS_PORT	\\xecd80189d28e131ca71ab2499128a01cf930b6fb203e91af2db06c6d086eca90763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
32edb62a-53e4-46c3-af24-ad71c30c326a	1	shared	HSM_DB_REDIS_USER	\\xf6e178d5d97f9d9ea12385a2be2162cb7a9c10c7903332946d6c2acf400d3e47c7763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
5f2a4ab5-d982-4c48-b318-4982d9536ba9	1	shared	TZ	\\xf5a1e409eff5ae14860dd0c6f2a4b92991a1f8c3edf3f274a706d98e38a5ae25b0ec3acfa8a30387ca0e63ddb4763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 15:43:00.803442+00	2025-10-22 15:43:00.803442+00
5cae6a38-7dfc-4cc2-9077-1fb5360a1b33	1	shared	ENVIRONMENT	\\x1adef71ccc6c319f953be36a1ea105b2f4ad82dec0fe1921fa436fe9598f6327d7db26763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
4509b70f-759f-4542-a64e-170a3edf376b	1	shared	HSM_DB_ORACLE_DB	\\x35719506d6f2da900000afad88973127163965d40a2c2780561df5253ecaaf3d8736763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
18d44c3a-6da8-4b04-a141-ee5bb9febd6a	1	shared	HSM_DB_ORACLE_HOST	\\x6f3ab12049f84b6f67a23b95064307fd46e061d062f59e6701653d7652633f5af06df7d520763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
92c79a38-aca5-469b-933f-373eaef18b83	1	shared	HSM_DB_ORACLE_PASSWORD	\\x81a374d52d7a7bc51926d47dc4d29368d89ac4ab3c3f39644048743960972000234d3bd83f763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
77e6e6fa-3baa-46a7-84b9-a50d5a838752	1	shared	HSM_DB_ORACLE_PORT	\\x455d9a7cdce6fc12b968da9dbba39f43e2507d39744b69f5dece62d49ac0b96d763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
1c7355b6-ff4a-4dff-98f8-59cd82ef3561	1	shared	HSM_DB_ORACLE_USER	\\xd13067c51d57f21ac1d1cd376ee7d324d6e038576c987376fbfded613865e6763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
12d9a0b1-7b35-4297-8340-0936f8467baa	1	shared	TZ	\\xb19caec11025adbfd6cc162b5b75f8cabd125a7ca6be93002406cb5e100c43ac4f4a6979f4420957fca9055823763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:46:16.992936+00	2025-10-22 15:46:16.992936+00
b9a4e186-a64b-479f-8f2e-b88d3e4a973f	1	shared	ENVIRONMENT	\\x3b3042b79d5073c68a1003898adff9896c7a6b947035fca07815277ad502e79c763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
6ffe8c9d-629e-4e8e-85e2-e7ea445cdd9d	1	shared	HSM_DB_ORACLE_DB	\\x52015fc7fce354fe90d057d14afaa943be69a10d4bfe40337782f2383a6fc435277e763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
d7dc98e2-e297-4b0d-ad60-129fa48ff43c	1	shared	HSM_DB_ORACLE_HOST	\\xc9c2d33e7754f88a413de792d603a12084a3f6629e2225704fca37a49a6c43e26e9c869123763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
95e23636-0e31-469c-a39f-6da3dc68255e	1	shared	HSM_DB_ORACLE_PASSWORD	\\x19394a7e63b605b1d6c4275add2906d70d0886da8772d7c92407cd165b0aaaf1d69b8618f7763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
413ac4bf-5e7b-47f2-8417-03853cf71308	1	shared	HSM_DB_ORACLE_PORT	\\xe6d535c9ecc4d14fa37bcf9cffe2b0b499cc5487aacf17e7b62ee3c82af1c7d1763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
7c884c34-76fe-499c-a551-284403a17b42	1	shared	HSM_DB_ORACLE_USER	\\x6eebfa9fd35ecd49e8fa3f9e67057433a4380b79e87077ce5ee11fe5342a5d763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
9de96d3e-a842-417b-aa55-fc16ec694385	1	shared	TZ	\\xf5f8064d41685df8b13b4b485fac1d50fd4ec16953262e056864de55745ea9352829250a179cbed4627baefd9b763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:25.610045+00	2025-10-22 15:47:25.610045+00
39318cb2-468f-43b1-92ad-7d3bcbdd9762	1	shared	HSM_DB_POSTGRES_DB	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:47:44.889499+00	2025-10-22 15:47:44.889499+00
f8d66b2a-e360-4880-8888-09aba6e54402	1	shared	HSM_DB_POSTGRES_DB	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:47.602063+00	2025-10-22 15:47:47.602063+00
7a0f7aa2-1090-48a0-9a6c-ee9341760557	1	shared	HSM_DB_POSTGRES_HOST	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:47:58.198245+00	2025-10-22 15:47:58.198245+00
a1a07c94-a74c-46b4-af8e-d47eb09ccd52	1	shared	HSM_DB_POSTGRES_HOST	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:47:58.487714+00	2025-10-22 15:47:58.487714+00
939f3f8d-e322-4c6d-8aaf-0828c6f9255c	1	shared	HSM_DB_POSTGRES_PASSWORD	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:48:08.702795+00	2025-10-22 15:48:08.702795+00
4507343d-0d9c-40f3-9fbd-5a9d3f832928	1	shared	HSM_DB_POSTGRES_PASSWORD	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:48:09.166864+00	2025-10-22 15:48:09.166864+00
84bc898f-3d8a-46a6-ab0d-e75d69487a5b	1	shared	HSM_DB_POSTGRES_PORT	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:48:15.375968+00	2025-10-22 15:48:15.375968+00
7a8d57a1-deef-48f4-bd38-bf8cbf16d9d5	1	shared	HSM_DB_POSTGRES_PORT	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:48:15.78646+00	2025-10-22 15:48:15.78646+00
eb095caf-0105-4ee4-8fb8-90ee00fbc72e	1	shared	HSM_DB_POSTGRES_USER	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:48:26.683081+00	2025-10-22 15:48:26.683081+00
2e86e860-8ca5-4aad-930a-683234c42103	1	shared	HSM_DB_POSTGRES_USER	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:48:27.104532+00	2025-10-22 15:48:27.104532+00
0c5b9370-3367-4f1b-b6ee-d150e183f7d9	1	shared	HSM_DB_REDIS_HOST	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:48:35.131062+00	2025-10-22 15:48:35.131062+00
dcf10944-d3f7-455d-ae54-d5dd02a81fc1	1	shared	HSM_DB_REDIS_HOST	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:48:35.650747+00	2025-10-22 15:48:35.650747+00
268fdfde-b09b-473c-bfa2-6f2cdc9280e8	1	shared	HSM_DB_REDIS_PASSWORD	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:48:43.305494+00	2025-10-22 15:48:43.305494+00
f3456c66-c295-4f14-95c8-6eb4a6f5c005	1	shared	HSM_DB_REDIS_PASSWORD	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:48:43.654849+00	2025-10-22 15:48:43.654849+00
d7dd4577-2b15-4e62-b718-cdb763235fc0	1	shared	HSM_DB_REDIS_PORT	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:48:51.319462+00	2025-10-22 15:48:51.319462+00
5e390845-64dc-44b1-ac62-004dc016d73b	1	shared	HSM_DB_REDIS_PORT	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:48:51.710434+00	2025-10-22 15:48:51.710434+00
c1aff9ad-72f1-44b2-b006-48e1ab24e02c	1	shared	HSM_DB_REDIS_USER	\N	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 15:49:02.47159+00	2025-10-22 15:49:02.47159+00
e0654ec5-c913-4ccb-9779-6ce74f91909d	1	shared	HSM_DB_REDIS_USER	\N	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 15:49:02.859626+00	2025-10-22 15:49:02.859626+00
74d58eb4-4dd3-4b1d-95f1-1ea5d932de9c	1	shared	JWT_SECRET	\\x7aaa7020127ee30971f8f8461b530199769db8be5c518d878b5117514826a48a08763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-22 19:08:40.616567+00	2025-10-22 19:08:40.616567+00
bd45e77f-94cf-4b7a-8bab-f43d1ad0ca9d	2	shared	JWT_SECRET	\\x2780de1f3c50240ea8e2f6af80a1161df10d288f6333dc0431809e02f6a57120181634db0a6a496d0d8a12d07b57d5dece9c25c4f665f76b75285f20108cf3d4b06d0d53044c2982cde50ec54614eb0782198b953a60d5fa62c435b15ad77d5452506dcda75f219cc96c30a2cf027c9a196aac0dc61c4f06396b15e5b53aa3000ae4b36e85db4c19b6eecb173cb8ac21021e6e33e31baf48313cbbaa763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-22 19:08:40.437349+00	2025-10-22 19:09:36.157744+00
12956605-eb20-4815-b613-103a631c0bd8	2	shared	JWT_SECRET	\\xf9513db05f2fa9abb1ae7dac701034d89f6dd3799ef309086760f65431f890dd5cfcbe457dd3be55435c8a92702c4bd255679ae3b711f34d2a5c8188158f15bbc684a0890d1b37a4d3fa7f96ac48f0eea6be7fe8419250ccf9160a5829269e8b0aca85dee41a8a2f9b7c24607347aca040303e60d39f07f481ebd15885c3b31e37e563f29594ed41f82cf4e4012d9933f5431f397dc749f22fcbd6a3763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-22 19:08:40.48241+00	2025-10-22 19:09:36.852731+00
7b836f0a-64f1-48f7-a121-0e0c93b97bac	1	shared	SWAGGER_FAVICON	\\x803cf61245787b6f8596bc262f5c599b51c7bf6dc6afc4d91f2277658966d6ce796691b51639e705d3c184a2efc6726213259bcef901c084e0065ad44d0dd2467d464585e2b979b495fe4501e4ba8bd8873b161a19dea69f6c5ddce040db9136517a6eb5fbb1f2d9f7c75fd554165c9971128aaefcfcb71e68f9538cee3b2c633bee86a1889a9bd827ee763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-11-13 19:48:58.214408+00	2025-11-13 19:48:58.214408+00
a2acc658-1236-4be6-bd89-0462d9e2f36e	1	shared	SWAGGER_FAVICON	\\x4d451ef9e8eaa2bd6abd79f6bdea4c26f6e463f16ca8bf141e0a25a24fbf1ad6084947d6fe0c1f749c9fae2177ac0380a290a43dfc99edf8f03f98bb058594738a2b3164dcc3334860198913aa2d9663281b7d973ff6193ac29d4b9337f1840a60a384b2c5cb3e8729de19fddc64e8f9e25ced4af4a6ae7820e78baa1d5d028016e53760684d33d0962d763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-11-13 19:48:58.327783+00	2025-11-13 19:48:58.327783+00
0ba2e93d-337a-450f-be59-90ef9a4f0354	1	shared	SWAGGER_FAVICON	\\xa4a74ff5e93e9a539919a7e5baeb5c6a9791283743326b6f7348cc9f8b70e935b44fe88bfda95fca12f7b1a8f6c21295588904d5cc2d3229d8961584fc307613d6198a3f8af219df1fe41b27cfe4aebbcda58095a25d792c13fe611396d8e94b8ae5c0f8f9b6337e7d472d675e751aae87c6170cf97c9abab93b3e318e251a9919f67382568c6df6c5b1763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-11-13 19:48:58.424705+00	2025-11-13 19:48:58.424705+00
42d0ba95-57e6-4626-8484-4a044dfff1f1	3	shared	JWT_AT_SECRET	\\xb55787317be0d81df009ade0489347e0874b9178271eb723b9189a298edb8b72d0763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-23 17:35:42.708282+00	2025-10-23 17:36:29.895846+00
06e337f2-0a06-4e0b-9f49-d3efd09ff23c	3	shared	JWT_RT_SECRET	\\xab93b6ba6e63a7e8094f7563d4cd0143db012ac3e5b72d98069509083601597a73763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-10-23 17:35:57.38247+00	2025-10-23 17:36:30.945353+00
6db71f89-6628-4785-b616-6fcc88d6f5d3	3	shared	JWT_AT_SECRET	\\xc13fc069b05806509f53fcf8cba0d17001fc3ce2c34a91419df9919d489a0b91a569998bd926f1494716ee747fe4908f71f598384b8d113a370ec779a467f3dda8d81fd81354f31e65a63224b6ba612ed9f9ad8cd1a81720b9498a2dcd9dbabbc5bca66692ea4d9cdbac925089e5e10bc28344f41ac6d3bef7fe92b1a729aa4698337a976ebb02f1ee378167c91fe53d9181745a2449fff792cd2c06763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-23 17:35:42.641422+00	2025-10-23 17:36:42.566867+00
56d0a993-664c-4535-a1fc-077cd07f06c2	3	shared	JWT_AT_SECRET	\\xf004ffecf16e4756804bf307e91b60c426d30677608997f32c64cc400b2e35653974c228d4d8191652c90fa52a9cef3e67108541835ad5e37a9debe182b9a22003fa9a9ca173e0050ece3ef8d9db854c0c65222654e8b8b263e52443f991bd4e4fb6403a673ae71e60baabfa3df3d0ea1219baf033701d219b350c3388ad5de39135ec84d555f14e9300f43c8b4705678218d5154d505cdeaa102b23763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-23 17:35:42.755673+00	2025-10-23 17:36:47.935739+00
18f239e3-f659-47fb-9984-0f098c4fa9b5	3	shared	JWT_RT_SECRET	\\xb89eec8c454229fecc1395827e06a73af194f1032781bdb38d400cd6162af50ad9a60cb4025854a31f9f99dbe504dbc58b18789e160f71c1bff22d02974a22dab6437e6ff0179d0e188b12afed4d13882c26d3b4643dd61fde6db803b4e920793343c0566916ab44f3171c01c7c8237b4948257282beeb88fec77a07d8ad524d99304b9495c5dcbacc5091c911d5b5a26e57040b578506d9eac9de98763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-10-23 17:35:57.450889+00	2025-10-23 17:37:18.766779+00
a9fbf5f6-5087-4104-be76-2334ecc92d80	3	shared	JWT_RT_SECRET	\\xf9e195607274742a0ec61e49226decabc92094b53779b2d547c70ec5cc4ee4dba134d2f64e8128d0713d635d5b59eef5488c64fef43a4797973d3ff95e8fab4431ba0372877199e675643b6a1db0ab162c8b25c1de51e5d71b7bdd1a8d8be50cf3e3c2505c17bc9fcb16296edc76725817f1290c6aa4d44466e2edc3b63a29b7d95df91b612aad62461d9634bfbd25ff42e9818d087a5b338aa1535a763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-10-23 17:35:57.302636+00	2025-10-23 17:37:19.420461+00
b70d991a-95b2-4f74-9c79-da202be4a4b1	1	shared	OPENROUTER_API_KEY	\\x4a01a17864a4ff9b20f7686a47578fcfe32202bb3114db744714a0806bec0949ab3389790f140a70137c8f3a39b14abaf53b6fa998863e49142e9871a003f4d25c07fa0a657a1d22e8790163814d46155f0164a5035e9cd1a00342901d1d2659bd81a60224763031	\N	\N	\N	f	\N	\N	e4511410-f276-46e6-82bf-074363964703	2025-11-11 19:17:13.553519+00	2025-11-11 19:17:13.553519+00
4bd4738a-38e6-4e60-a7ad-ed60e96cf856	1	shared	OPENROUTER_API_KEY	\\xaf2eb8a1e4ca4c6ee7bb906c79f76529984ffc518d2049c05be8d79a2a32eb53a9bed34a9b5462991f4922b6d3ae3eb578e35801825b4e75aebe1c7a972b9d5b1a4d42333e593c262e82bdb51b0e515f38f24917b331bad31fbf0e5d75e14c7b4165c0ea18763031	\N	\N	\N	f	\N	\N	05c2e293-0bfe-4acc-81cb-0b04ee0a5566	2025-11-11 19:17:13.557639+00	2025-11-11 19:17:13.557639+00
b56618c7-256e-48ee-aa3b-d63b450a71ee	1	shared	OPENROUTER_API_KEY	\\x4b2065820405bd47984726c70da0013e1c71d3fc083fe2f6464e00c76a8accd4427441a691a512441ea3f451d16490809fab93c03e2ca75307eb458294351c562b832bb5375fd161c9bad8f5dca7dbc306f3088305bdbafe15b897d95d5ef77468c6957fd8763031	\N	\N	\N	f	\N	\N	8ae0e6fa-1c96-4b4e-a9c3-9f64c63f6ebe	2025-11-11 19:17:13.56251+00	2025-11-11 19:17:13.56251+00
fc8711bc-3242-44b2-b242-f88aa63cd5e4	2	shared	SWAGGER_SITE_TITLE	\\xd74ddeae016c85bb869ef9348c0333db985611dfc9ff1361c77c3ea429799964b19da593535e4eedeb12d1897c75c55e34cfbf3bc9af452ec2763031	\N	\N	\N	f	\N	\N	04c8a5bb-668a-4207-a189-3549854ddfce	2025-11-13 19:49:18.844206+00	2025-11-13 19:53:54.299754+00
1394efef-0624-48b8-89ec-2daf7438a22c	2	shared	SWAGGER_SITE_TITLE	\\xdd5876a9ef6ceb56c2726a053e1b50481e908f06cafc2ebe26be4a61ff20617c27dfe0ddb7a17936ba6d39169ba561fc54994c1832c1f62b42763031	\N	\N	\N	f	\N	\N	2707578f-df91-451e-80b7-f2fc488e815a	2025-11-13 19:49:18.891875+00	2025-11-13 19:53:54.325722+00
65a363d7-68db-466c-83e7-7a1d72a42334	2	shared	SWAGGER_SITE_TITLE	\\x7b983586d655084b01e9e0f53993a6989b1d6be409b6acfa150cc4c7e7495b86d813dcd240609fe05ea09dc142842d086a11dbd91dfe1feb98763031	\N	\N	\N	f	\N	\N	5bc6e6bb-7529-4395-abdf-bd66d0adb699	2025-11-13 19:49:18.892096+00	2025-11-13 19:53:54.327055+00
377396f2-51fa-4c56-ba55-520968950a40	7	shared	FRIGATE_RTSP_USER	\\x830342c7495bdddb44b4f091eec82f68847e2b3639102399c496ff1a75fa5f42bcb94c42e1763031	\N	\N	\N	f	\N	\N	2060d386-1de0-4d43-bb57-ad4833fe317d	2025-12-08 17:39:22.916864+00	2025-12-08 19:08:41.599798+00
0b4c3c2f-a2b3-4fa5-bfe4-b04a1120933b	4	shared	FRIGATE_RTSP_PASSWORD	\\xe62d552c239768ad7864a65880afe4b9bcc504f1c8cab1f19b1db06584dab622b56746b4332ec8763031	\N	\N	\N	f	\N	\N	2060d386-1de0-4d43-bb57-ad4833fe317d	2025-12-08 17:39:39.319803+00	2025-12-08 19:08:16.952243+00
82252a1b-031d-47d4-87b2-9466d250a8c9	4	shared	FRIGATE_RTSP_PASSWORD	\\xb2d43fd2c04edc7db518a357f854fc9368bff8d6f1a47f17ad4c471bd6e561efd9dc73e20d5855763031	\N	\N	\N	f	\N	\N	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	2025-12-08 17:39:39.321736+00	2025-12-08 19:08:16.989933+00
ea81c8b4-8167-4066-8274-7ee811a3f2b3	2	shared	S3_PORT	\\x076958bda0d0f3c80b0725434361a2cc707b6d5376548502363eba7bf83c1c763031	\N	\N	\N	f	\N	\N	46346785-4314-4bd6-928f-e09d54847e98	2025-12-10 16:48:51.240533+00	2025-12-10 16:49:13.062469+00
3656a0c4-d7aa-406c-abe7-4f59a9d91d5b	2	shared	S3_PORT	\\x01743213e5684ec1450a6e541a19eec5c3fe754586d5e505b9b747135e9ce0763031	\N	\N	\N	f	\N	\N	ed0fa5be-f07b-4aeb-bddb-5068d048c889	2025-12-10 16:48:51.236674+00	2025-12-10 16:49:13.50959+00
2f685321-31db-4dc3-8884-a12a60064b3d	2	shared	S3_PORT	\\xcef4c836e4d4967095f585a256db7d9897ed3ec79b2a01568f47616ff55b86763031	\N	\N	\N	f	\N	\N	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	2025-12-10 16:48:51.245139+00	2025-12-10 16:49:13.985117+00
53c329b8-0679-487e-8838-ccb31460911b	2	shared	MINIO_PORT	\\xdd45581d8919bb9285263ef49331406c677ca6fd712f2e72fe29775140579581763031	\N	\N	\N	f	\N	\N	94e67651-7c8f-4de7-b648-f9632e94ed99	2025-12-10 16:52:14.736868+00	2025-12-10 16:53:11.163002+00
65cafe79-890c-4fe0-b4c5-8a8019a8d8bd	2	shared	MINIO_PORT	\\x6c19d8eafda0f8106e9936bbce80ee7020c18cfef4f1dbafb323ebb7f42c4cf3763031	\N	\N	\N	f	\N	\N	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	2025-12-10 16:52:14.753623+00	2025-12-10 16:53:11.612794+00
a43e7f4b-d339-42e0-8edc-fa3ceb1b1448	2	shared	S3_HOST	\\x4e96718779c0d1b0233ba4fff7f659ed3ba57ed093cc78263d81dfb8c8baac02376797acd64d170cbe556c8d1b81d6763031	\N	\N	\N	f	\N	\N	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	2025-12-10 16:48:41.883594+00	2025-12-10 16:49:46.684061+00
158877fc-94b2-4f3a-a4c1-905aa4a31c82	3	shared	S3_HOST	\\x80d3c91cf8dd4a1568d95dd2490c2b7937880bd1ead5bd09c65f8590de73dd28c010989c83923314c0abba2fba6207763031	\N	\N	\N	f	\N	\N	46346785-4314-4bd6-928f-e09d54847e98	2025-12-10 16:48:41.883074+00	2025-12-10 16:50:12.826913+00
c7b80bc2-ddc2-4978-8101-f3f8812d8fe5	3	shared	S3_HOST	\\xb416d4727932340b42220f6116078f72254c39d3bf9e6f66bc326ba6bfd3c78343279479332da8210d29dcec32a9e2763031	\N	\N	\N	f	\N	\N	ed0fa5be-f07b-4aeb-bddb-5068d048c889	2025-12-10 16:48:41.88545+00	2025-12-10 16:50:13.309292+00
401c36a6-fa1f-421a-9cf4-b474dd3e2a5e	3	shared	MINIO_SECRET_KEY	\\xd940229ef1457b4930c4bb8c327ca30d06f9138fafe223a9930bbdfe32580705d6e822c5763031	\N	\N	\N	f	\N	\N	df55f1e8-12b3-436c-84b4-270f7a54c1c2	2025-12-10 16:52:37.689716+00	2025-12-10 17:09:06.094908+00
0544db56-558c-4290-bdce-b139cae21e6a	4	shared	FRIGATE_RTSP_PASSWORD	\\x262579b92e71cebe8e8efde7931e9dacc32467dfdb3d70ded4af5e93a8fc48341c76cb2f0b03d0763031	\N	\N	\N	f	\N	\N	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	2025-12-08 17:39:39.310792+00	2025-12-08 19:08:16.976662+00
45d2e9d2-50de-46df-a62d-002bacde0220	2	shared	FRIGATE_RTSP_PASSWORD_TOMO	\\xdd916ce19ea6fa2d37f048424011b0ea324f018e83ae26c65a11e131ee2ae95f763031	\N	\N	\N	f	\N	\N	2060d386-1de0-4d43-bb57-ad4833fe317d	2025-12-08 18:41:13.37774+00	2025-12-08 19:08:25.216117+00
62d14a21-c3db-4a15-9e7a-b08eb3126629	2	shared	FRIGATE_RTSP_PASSWORD_TOMO	\\x42f9cf01f10294dc44cb4defb503612e9b5240b5c2d2380b92f8a2e9cb754b27763031	\N	\N	\N	f	\N	\N	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	2025-12-08 18:41:13.414558+00	2025-12-08 19:08:25.226337+00
3a5f1d03-a3b9-43ba-9822-727577967d0e	2	shared	FRIGATE_RTSP_PASSWORD_TOMO	\\x874ec46aefac3da2dd6103e6e1ea9c6edecfc8ee004988a1e417a8219f68bafe763031	\N	\N	\N	f	\N	\N	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	2025-12-08 18:41:13.422325+00	2025-12-08 19:08:25.230399+00
1553c8ed-ceb0-427a-a99a-3b1892ea4228	2	shared	FRIGATE_RTSP_USER_TOMO	\\xb7637806e56b2521ec2cd65e2afc4a257ebc4e85bce68b45a237dc96803200bde49161029300763031	\N	\N	\N	f	\N	\N	2060d386-1de0-4d43-bb57-ad4833fe317d	2025-12-08 18:42:07.081137+00	2025-12-08 19:08:31.699833+00
81c12fa8-b20c-4741-b825-377651e5fc2c	2	shared	FRIGATE_RTSP_USER_TOMO	\\x97b1bd3e91ded4f25786d515cf1d5b135af2bbc9d02d5a9c97871e280083765116673522cf91763031	\N	\N	\N	f	\N	\N	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	2025-12-08 18:42:07.100926+00	2025-12-08 19:08:31.730279+00
d522fb8a-00c4-4983-b640-453e7db9a6ed	2	shared	FRIGATE_RTSP_USER_TOMO	\\xc54131e992cef7aaad1d13749344fecd7741a87e15b998d2855cf943b6eae4ac3bf9c08e4f11763031	\N	\N	\N	f	\N	\N	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	2025-12-08 18:42:07.099143+00	2025-12-08 19:08:31.73199+00
ecb331ab-05ef-49e1-99a5-2d0664349759	7	shared	FRIGATE_RTSP_USER	\\x1aeecc0241ab78a1fbd2d7db4bf0cbd8f79fb718a7d512d65a974e2c88acca2c9fa4e573b1763031	\N	\N	\N	f	\N	\N	ab6f75d1-f8e2-4dcd-aeac-fa564b1b0346	2025-12-08 17:39:22.947442+00	2025-12-08 19:08:41.618192+00
48227d56-f097-4545-af4f-faeb8366f649	7	shared	FRIGATE_RTSP_USER	\\x1fa509f4d5d1559b1083418716d0f1fa246bdd641fe92acfc4e5df0a8456bdc9dbf7a71c94763031	\N	\N	\N	f	\N	\N	7768ec0c-5b63-4dfc-80e2-abc6f4117dfd	2025-12-08 17:39:22.953181+00	2025-12-08 19:08:41.621223+00
cece50ee-4245-4c5f-a407-58970814ecd9	1	shared	MINIO_DOMAIN	\N	\N	\N	\N	f	\N	\N	94e67651-7c8f-4de7-b648-f9632e94ed99	2025-12-10 16:52:08.193094+00	2025-12-10 16:52:08.193094+00
1580bd8c-6db6-4f7b-9610-b8e51c23d301	2	shared	MINIO_DOMAIN	\\x40aed96b3242944e1db95f43a301fc81e1c349292869a323b35acca4d1892add02c07da1bb763031	\N	\N	\N	f	\N	\N	df55f1e8-12b3-436c-84b4-270f7a54c1c2	2025-12-10 16:52:08.240495+00	2025-12-10 16:52:57.341655+00
f62ce38b-53ba-45ef-9663-e4fb369b7865	2	shared	MINIO_DOMAIN	\\xdddc0f07272439f6884e17d94fbdb3ec730e549cdaf52cc630c5e55fdb34bd56140122c63d158fc072cd9572622fa3763031	\N	\N	\N	f	\N	\N	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	2025-12-10 16:52:08.247305+00	2025-12-10 16:52:58.02922+00
e1feb93a-7336-45f4-bba3-b0e866107799	2	shared	MINIO_PORT	\\x0b785b719476b36c6126bace1e9d4d18c4a68e627b5b7cb8ef74c7cea05772fd763031	\N	\N	\N	f	\N	\N	df55f1e8-12b3-436c-84b4-270f7a54c1c2	2025-12-10 16:52:14.752662+00	2025-12-10 16:53:10.393744+00
3144cb46-7bd1-4d6d-ad13-41134a18bccc	3	shared	MINIO_SECRET_KEY	\\x23afe5033097a1951521b21e131bd20d2afbe96e144e7ce958ab94fb61aa03c4de6289e1d368698a763031	\N	\N	\N	f	\N	\N	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	2025-12-10 16:52:37.690513+00	2025-12-10 17:09:06.095527+00
46f68df2-6d5e-4d76-8264-71368a448144	3	shared	MINIO_SECRET_KEY	\\xa8212a574b8c71dc8cf95fa856fd0628d38cf5b7e4df279063b81e9d69c026e62a158a6a763031	\N	\N	\N	f	\N	\N	94e67651-7c8f-4de7-b648-f9632e94ed99	2025-12-10 16:52:37.668892+00	2025-12-10 17:09:06.107528+00
1ccc79cf-7ac5-4712-a0fe-bb50306ff6b6	2	shared	MINIO_ROOT_PASSWORD	\\x8a4db9c0310c735d148b24ce4ecd1a468f03f8c69385be9a0e02ceecdb2a36810bc662a2763031	\N	\N	\N	f	\N	\N	df55f1e8-12b3-436c-84b4-270f7a54c1c2	2025-12-10 16:52:22.55335+00	2025-12-10 16:53:54.385035+00
defbb33b-11a9-4023-afe0-581e24be3824	2	shared	MINIO_ROOT_PASSWORD	\\x35992604a4bf89195baeeb6669762840b292a9430b7365db52cc445a8f621aaa774cbbb0763031	\N	\N	\N	f	\N	\N	94e67651-7c8f-4de7-b648-f9632e94ed99	2025-12-10 16:52:22.526357+00	2025-12-10 16:53:54.892298+00
7d889cef-90b5-42ea-8fbc-519b35aa9849	2	shared	MINIO_ROOT_PASSWORD	\\xdac523130b36380613ea79f954156991d10da644dd18b366e9a6014c50ea001e818fdc587d2be21e763031	\N	\N	\N	f	\N	\N	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	2025-12-10 16:52:22.552497+00	2025-12-10 16:53:55.307558+00
bcabc74c-544f-47d6-9048-74b2267044d4	2	shared	MINIO_ROOT_USER	\\xf4ce2c1fda46982cfc0a864667b5c8a27f7d38a8fb05c3c61364773c80f13a4c17763031	\N	\N	\N	f	\N	\N	df55f1e8-12b3-436c-84b4-270f7a54c1c2	2025-12-10 16:52:28.827289+00	2025-12-10 16:54:09.613495+00
4d5042f0-67c4-43b0-8619-0bda5a6eb3dc	2	shared	MINIO_ROOT_USER	\\x907417d7605741ef748ac06df000c3c98e2de87ab1dc763e05bcd5ce60da6d5aee763031	\N	\N	\N	f	\N	\N	94e67651-7c8f-4de7-b648-f9632e94ed99	2025-12-10 16:52:28.810843+00	2025-12-10 16:54:10.126848+00
5347e33a-f145-4d87-bb23-2778aeec61b0	2	shared	MINIO_ROOT_USER	\\xc86ee89fe57998df19454fcd17f1693eeeea0ead26b6b807b919be40f6254459e2763031	\N	\N	\N	f	\N	\N	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	2025-12-10 16:52:28.829934+00	2025-12-10 16:54:10.582774+00
834d1c2a-5342-48ee-b341-54d2d83bac7b	2	shared	CLOUDFLARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	46b4244c-c2ce-45ec-891f-7dd38d86e753	2025-12-16 21:19:27.77441+00	2025-12-16 21:19:57.889901+00
0e9594fa-cd11-4a9e-b31f-81a436b44bc2	2	shared	CLOUDFLARE_TUNNEL_TOKEN	\N	\N	\N	\N	f	\N	\N	dca4e684-c441-41fa-91d1-986fcbbf14c1	2025-12-16 21:19:27.773564+00	2025-12-16 21:19:57.911829+00
afc23972-1748-45c5-9a31-8732b095a451	3	shared	S3_SECRET_KEY	\\x2dd60f1f218353db4eb0a9c998f72ed107d020540135f54720ed87478cd04a41b90c4c163be30e6d0218bc6a63be52e2e8ae3b8647b3ac5e407ceae94d71a4a22471783e763031	\N	\N	\N	f	\N	\N	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	2025-12-10 16:49:03.468365+00	2025-12-10 17:27:22.363817+00
1cb18d18-62f3-491b-a38f-149da3258582	2	shared	S3_ACCESS_KEY	\\x72af34e0bda796d49b53d45d26bdb56cc08808d2b78366c879bcb44c8782990366763031	\N	\N	\N	f	\N	\N	46346785-4314-4bd6-928f-e09d54847e98	2025-12-10 16:48:04.68972+00	2025-12-10 17:03:47.569409+00
3f437eb3-cf93-4a6d-ba90-e70a99e71015	2	shared	S3_ACCESS_KEY	\\x5ba6c659e2e649a82dbfddf9132d7adae1a38b0ab3a4a3318fafe6a46ff9973c6e763031	\N	\N	\N	f	\N	\N	ed0fa5be-f07b-4aeb-bddb-5068d048c889	2025-12-10 16:48:04.69604+00	2025-12-10 17:03:48.250363+00
e07ac864-e5eb-4735-9b51-19053524df41	2	shared	S3_SECRET_KEY	\\x4901e35f496df70f3bbfc1e24e9a79352628fc132c39bb38d31c3fc2ad66dfd4d6f62516763031	\N	\N	\N	f	\N	\N	46346785-4314-4bd6-928f-e09d54847e98	2025-12-10 16:49:03.468945+00	2025-12-10 17:03:58.886119+00
5c3e9799-4dbf-4125-8ed0-e4cc2fc43a5c	2	shared	S3_SECRET_KEY	\\x5548e8f99a32e2bc5e79cdb952a8b0acc842d174117739722d51536caed70ed6ff5d8d81763031	\N	\N	\N	f	\N	\N	ed0fa5be-f07b-4aeb-bddb-5068d048c889	2025-12-10 16:49:03.477788+00	2025-12-10 17:03:59.504337+00
3e31f59e-79db-4fde-b1c9-91e0d1796bf2	2	shared	S3_BUCKET_LOKI	\N	\N	\N	\N	f	\N	\N	46346785-4314-4bd6-928f-e09d54847e98	2025-12-10 16:48:15.115873+00	2025-12-10 17:04:34.093493+00
3d2f056f-8b25-4d64-a955-64b5f40eba1b	3	shared	S3_BUCKET_LOKI	\\xa104c7194b99284a3bd7e2a1c5e083ad98ae1bcf17cdbc9258e7be0e7011d729ddd0334aa15f208ed87f0edfeb7d8a763031	\N	\N	\N	f	\N	\N	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	2025-12-10 16:48:15.122507+00	2025-12-10 17:04:34.109991+00
89bddcae-b972-4e07-a4e4-d6bafa879c4c	2	shared	S3_BUCKET_LOKI	\N	\N	\N	\N	f	\N	\N	ed0fa5be-f07b-4aeb-bddb-5068d048c889	2025-12-10 16:48:15.132753+00	2025-12-10 17:04:34.116454+00
98bb7e4a-3abd-445c-81c2-1d405a19eaaa	3	shared	MINIO_ACCESS_KEY	\\x6e04d1d4c965ad4aa9d4300355a9ae4ad825084ad0a45f9dfff7364cd840f9d5c6763031	\N	\N	\N	f	\N	\N	94e67651-7c8f-4de7-b648-f9632e94ed99	2025-12-10 16:52:00.593339+00	2025-12-10 17:08:55.906632+00
ea87e63f-ac44-4598-8e60-febf81835139	3	shared	MINIO_ACCESS_KEY	\\xe7858bb49690f6115558d0ceef1104df2eb971dfc7c8c39eaae80bcd2e005907e7a2dea6763031	\N	\N	\N	f	\N	\N	a3c8a4c3-2a72-4f56-ade7-54f999c5ef85	2025-12-10 16:52:00.592065+00	2025-12-10 17:08:55.91174+00
d5c29797-6578-4b33-8814-ee45e548ca79	3	shared	MINIO_ACCESS_KEY	\\x2a4e6973315b49cc70b22b44b6a7492766ebc6de433f215ef17caa34f08e65b154763031	\N	\N	\N	f	\N	\N	df55f1e8-12b3-436c-84b4-270f7a54c1c2	2025-12-10 16:52:00.589441+00	2025-12-10 17:08:55.91256+00
c7801ab7-06d6-4ab7-8689-9a74d24fb6be	3	shared	S3_ACCESS_KEY	\\x83669335d7bf3315764e39330a3f96613165963cb7d63e9a5a9b3069f7dddc841220d4eca2ac40f3bd6c9ec2c77ff092763031	\N	\N	\N	f	\N	\N	0855d279-fbe0-4b51-b7bb-234a9dbb8cc8	2025-12-10 16:48:04.66952+00	2025-12-10 17:27:23.809885+00
69acfb44-8f7c-4caf-afa0-008179f9640d	3	shared	CLOUDFLARE_TUNNEL_TOKEN	\\x07ef7df91a9c77bad6e3e60d459fab74e7f902aeb5031a4e062a6e88d1f88034e69f66a75a60b1f413ab4495cf73840964f98ea1625c4206bbd72f9abb2e23e9370946023c9b0099d7964d2590d2d878676ca704343b12091e3ce421f6d9a0a2c942ddfa68ae02e5d80c464e2c596e7b37bcd559b376b7409eddc6afec8fecb0edcf41999e9aab4feec1bc8e9adc52bd204516322a7f640e880f869f6ea10013e6d7a32f4feb8aab1fdea1a7c5716bce378376c0a195a18bce6a33712e23269944c2bf95a0186fbcf5461f6133f26574e9ca73c6763031	\N	\N	\N	f	\N	\N	73b8f6f1-9a6e-468e-8df8-c4a3cccfc7ad	2025-12-16 21:19:27.765223+00	2025-12-16 21:29:01.644212+00
\.


--
-- Data for Name: service_tokens; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.service_tokens (id, name, scopes, permissions, "lastUsed", "expiresAt", "secretHash", "encryptedKey", iv, tag, "createdAt", "updatedAt", "createdBy", "projectId") FROM stdin;
\.


--
-- Data for Name: slack_integrations; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.slack_integrations (id, "teamId", "teamName", "slackUserId", "slackAppId", "encryptedBotAccessToken", "slackBotId", "slackBotUserId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: super_admin; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.super_admin (id, initialized, "allowSignUp", "createdAt", "updatedAt", "allowedSignUpDomain", "instanceId", "trustSamlEmails", "trustLdapEmails", "trustOidcEmails", "defaultAuthOrgId", "enabledLoginMethods", "encryptedSlackClientId", "encryptedSlackClientSecret") FROM stdin;
00000000-0000-0000-0000-000000000000	t	t	2025-10-22 15:21:25.252932+00	2025-10-22 15:25:08.349076+00	\N	c21cb427-2ec1-4249-8ac6-cde8415d0863	f	f	f	\N	\N	\N	\N
\.


--
-- Data for Name: trusted_ips; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.trusted_ips (id, "ipAddress", type, prefix, "isActive", comment, "projectId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: user_actions; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.user_actions (id, action, "createdAt", "updatedAt", "userId") FROM stdin;
df569d7d-21fc-45fc-9c4d-2fca3915d23b	december_update_closed	2025-10-22 15:28:05.170809+00	2025-10-22 15:28:05.170809+00	0c9fba56-8584-4a79-b9ea-183147b9d42e
\.


--
-- Data for Name: user_aliases; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.user_aliases (id, "userId", username, "aliasType", "externalId", emails, "orgId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: user_encryption_keys; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.user_encryption_keys (id, "clientPublicKey", "serverPrivateKey", "encryptionVersion", "protectedKey", "protectedKeyIV", "protectedKeyTag", "publicKey", "encryptedPrivateKey", iv, tag, salt, verifier, "userId", "hashedPassword", "serverEncryptedPrivateKey", "serverEncryptedPrivateKeyIV", "serverEncryptedPrivateKeyTag", "serverEncryptedPrivateKeyEncoding") FROM stdin;
e7e03fff-c71a-4f5f-9fcb-f0ee6b7cf0e6	\N	\N	2	D7tCS//96Z57vi3+lX1w9iVB0q5rIOO17k57CSYle69S8CeUtPU9vU8RGzoW8b02svTeZg2oHJUb1+ugkjuARw==	T8LwE94BtpPgdf3e	bcp/wIcvRJLlN3ZFM/eHnA==	jXc/M4bClcLb1118wGPzOLZKvm/2x/mzR6Qu676/anQ=	Q59Dj9eEh+9P4nndzpm5Dpa1trgWcJ0I8Jt7qo/PILZ3qUDJ6wKkOAP9jqk=	pP7AugAeDUGtR5lp	5eDUCWwYGqvYFJIrfPHWIg==	9550191fdb54b8407d5c6b6f720f99bc34713d0b432b82e22dd77ebfbadf4239	a5c1c5caa9ca7a82d8b6848eacf12a2982cec1b4acc9ae68fd78a03c6c7388fdfe82c426476f1059908304e0b540549a8be2cd73143a6920d514ae097d3c0d48f6a5ee94d78025c2eaaf926abeb45d914d05288dd0ce38c24400ab6facfd471213f3b3e81dab57cc04c25a402e8bace53194e9c0ebd815bfbfc2c3e34df24b9179f6514a45e267d55b752d878f7cdb7d62bbed20d99dac96b4b780cdf9e98bcb44e65dda6517eb854e56d9df34f802b16a5bb772687375a36f09791aaa7f788f2d093c67bcf57ee83f9763b829bc971e5c8476e49fef1257e4e695334d3a7e9c7c6f50ce6ce4befa68f961edf69451a3a9c947adca45a369a6bf78f482d0637277bd8a7e28c5183441074937e7f058c256783f8d28324c28787e311d05b6aaf2f26c9627b63f48866695bc9567faf8dfc42cb1f89f455c80565d90f2c3e314f8890ae8172cc2a10817d24ea71a8e9c82c367eb278517a453ad207c92616b4e118325468de9e563008caf518ac565f3a95af45e69955a4d51a544d48dc00de2ff9607b86d28bf09f41f24c57542a5ee1d456b899083b2fc83e8b148ec19eddbc2156a822c97e743282120dd368d6b9c703b104872c75d2f8fa1f4dbf1649c47ff281b2e6c7594d3ec9d7be9d51faeb7714f02e5ab0eb0672e25ea82536439140a5fe511b685e8b5ff259a428eb935e40b597ba6a6845d0b2e19bd380106a2a5c2	02d439fc-3f86-4889-9792-5cf3bad6f46f	\N	\N	\N	\N	\N
f5055725-3160-4a06-826a-70d1cbbe4a1c	\N	\N	2	c6EESFujja09SlP1H1t20E5kmx1vMJSj+oOPi+hoXrnn2pFdvJ8VU//PfcoZ7u/Vc2X1UFmH2sophCRynrnOIQ==	5LoItjHPS0HUXD0s	ulka9owOtJKqByIjMVPBSA==	WeCwK6cTgWNpSxk15OjJDTOKrDAVhZMswxkxad4XgS8=	X21o28zbDQ86zkGxPrIYgy/+AoZN8cG1GA+1Un0DQk8v89tsbyMhkpfEYw4=	ufa/P5Uk/eoUnifb	3ebIlg6Al19zHM4kLXr1eA==	0cfc0a03060e82315d81a4286390334d96ae0dc392f96ce140afb277b859c57b	397d102b8fc4477f454143edef5b593bc6bf2720fda28967b3d50edf8127bae0d486bb39b60ab484cdba3d7eb3eec3f13fb697be9494bb5c1c0ce0b4927104c85fa34d3ecd37720e22d10701cae8658200388adfbe9876bf0f6916d08533a00ce714fa1a0b7d5635d5450fa70fcfbaa6d658899d02189d14ca3a35c9ab805e936024b845f8dfff7d7598602fc1b6be51f9ab6323c9f71d9138d1badd8248eddbed4263e23113c8d1572bf9f865a35bbe75d49abdb7089c2bac5de58f26c953ac89a27c8a25bd158cd8fe50aaa75b39ab113cf6f8226e44d9789304ecad763be633650904b20fc247f0d5602f4f6d52b0091c340866873d96faac50349e0f3729b906f949671a71814368a8a535475ebd49a69a19f6808eda569aed98b47ff718e320b055bda3ebc327f7494a8fbbf25684bb84331245a185d661f198ff75d7e72beb36bb8c446ab5611ffe7ddf3afe2869ea878318767e57aae425c1bf982c571f91aa22a7387aec6d01f923a1719a2f0817b80ff75397dd88cf725c9959b3f046fa6e39002b4fcfd4ae1878e80746e9b91ebe8de1f0a0f6c8eb33258f267a6031e78ed233931f153a85c7058cf5310882e3fe44923ae25707247699ff843e0c6688ecee1743b23c54cee98e7ca62dbb37505924f513eacc58ca84bbf43ba8b2fdcf880cba3c92c315b2cb1f8d27bc2d5fe99a76c1e2406e4c5449b2c6e189f0	4bbbf546-f610-4234-ad37-1c3c72f95747	\N	\N	\N	\N	\N
44f2f8d0-25a5-4721-acb6-ab14c3117d4c	\N	\N	2	dKwJy8YtoCwbWvxP2ZFgF2IEfcwYVFjXw3RCdDm1285ybIHNdqdtRoGYPTU1a/yy+iFh3H7+cqx6BBcKhIUmig==	jykVRZqcJfvf97s1	xlL6h7WhXVJ5me5ZvP1CPw==	QIz3MAoszLBY0Y0ATtE1twK1HA7+dhHoptG41uAFSwU=	suE+PieFzwxLVRlWEfizxenp5lqTLTrQgfznKmqUzb5VnYPF7n8bQxrs+A0=	uPhig/F1PzKLTiK6	TXeCaKuY14LPQv4nmWoBWQ==	b293bf8751f624fa1b8f608b95052d7c0bbf12d83a08797196dcee39024783f1	135f545ba05243eb6debc8fc33505008c1a144f0ec36502c0a33e7c78cf7939364bb2231d2416dfcc3d5e1bbd09799336b4be4145acd67de64e3fe16e58fcd87cf65d143fc66d6d1ad7ef4f89f5cf792c8701696c13fd38fc52d343e8b3b0b830a9470996360ab0e3023ad17bc4ab326ed1923ae47a31bdf15317a55956a9a4d61568bbf986d0bfefb494406466b3d7f74509fccbcdc1f26f835cf5a0079789ccee8e00df0e3cfc4139e20082ab8f9f1c42349b8121b8c7ee4cb04c5ac2e415670f2b317c4e0ead82e9c0551d6aa3ca1acc8720428f304adb35e47a35a7a43601a09102af91012c70e35635889e05a883c8c9840da41f18ab863831b979338d16c401f54df1a548a28bf250e39f395b55b7e2c9d42cea364758121e61ef3d2d057eb0c1bcef8d0d1ea7d09a661e89f562a8d1bf93b273b896d749a5fc79691b18360b5dd389e5b254f15600e96162b9bbe1d83cabd6134b7f38ece242af736312cdad46acef82b13da89fcf6d0e8e4fa46cf9507f4379df25572765c1516dbfcdeb74c8489ad64040d59a022a76934610982b2326e1974854df6e41ccc218fb20811f303b1972ac4c6d6cf4fc7749f195460a38629d92f26d94fe2fbd8a854b3774aab858b871ad01ae761f306845ffe10366a6c209cb5c33ab4e49c6f9e2130f8e6c4452cbb703864bf6653644d0da3513610f720ada64b41780d96506ba34c	af0d16ce-271a-485e-81ae-37d56c4d8571	\N	\N	\N	\N	\N
32dd066c-2d74-48e2-8e06-a7574c256a36	\N	\N	2	cC5jOiYI3mkzGttLOVMuecwUpGUS9EqWZn+P8pvpWHT0fL9rcaNeu/xJnhfJzd+f05nIrEFfr2dIs+okRKHMKA==	g58R7pVK+qlAtbIa	OcVPcPVbSTbWuvVF5NszSg==	ndjVuYX5unPdtXJXUyPna0cuzONHFs/KZTuthJ1+owU=	WzZT6Az6qbzLUkmUUld3M/19qEplFQI8+d8VGnKAKGbWZ3r+9PSoUs6sZrY=	iO60EMuE11x1hMwd	dbO6GbcdF0/Wcen3R8jLvg==	4afebf01731e995016236942b8432eeeec4475b7b000ae29674b821e01e48b2a	6188cbf47e8afb7dac25fe0fac785175546a7db3a2b756ad880956db0b2ee7b40589454414af356db2ef6783e20d25f6487b724223fc0faca0752c4dc84d4eb2519add772419cc4bde82973f38a29bd9ead47aea606e60c84da84be60ba25f07e516233bc013e2eb99fbd395ca748fb4b0d08beeb14001320aa5c0da906f28faea46137a5a37b4a4d81484622ba5c6ae5973f4cbc1f7f214298ed71874d0a6f483bb7eeb53a2eee34e82d2b0ba32faec823e596b1368513c0581a758138cea09427a2732801d936ead44efe9a1cb8b810b504ab553e8016809b8923f551f4c4848fba8a4e96035e98882cac50c9eb8a43f33ba76d0ed31fb6d95a9a02783edc8442f81e86a8cb842f2819d5a49a8b2fe6810a3d73c00444c0d2cba5636d964b568f0d6cadac2abeedfb5562887d72d470b681f816379f01acb6ed5e964fbe0ce13457318f6a87bf9faaf061b4f5ce7a7b39d96fb6fd7a15936bfdf16346a3fc7e87a3e51d66ee38c37b099d71ec9925a80f395574eb8e424337bf1dc29ce86e8138f3ba63f8173a9bb808e965ab12934d5ed3b7b0dcd7839a58fc104812145bd16b9df2b242fdc53a3a5df76842487781916b42e2165c0c7a566e4e0ae4ecbcefb16e78bb4d9ef740c6ab0a7e978e728394a8de8f442f0251f0329496fcba137e5fea6885ce7e1b2a46070a3ff3d5370dbae4c7c0ca085a6c2c928175afb0f07	00155375-154c-4c18-8331-92a36dc7ff1b	$2b$12$1gnaoKHTfyKW9eASj17zDeVKZSync97eSsLQmDj543tgLbfqboaMO	u499/4YsfFN08PZtxMcUwz5D2i1SWuqeBcW2Fo+ESrAZwenAPdFJGR+0iAw=	hsAcAw44UWfChwC11bNQ/Q==	XoqCKvCDS8jQqwa7EVcyGw==	utf8
92cc7716-ee4e-4c82-bec2-2cb517b9389b	\N	\N	2	2MKQWRhaiNClHIxyXN+cVM6I4famgonHOgKYg3F8awGHhePI/YnM+rrou5J1Kp4W8SR2QTqm+lfg6wSN6+tCpQ==	lKI1F8ReFuQ7aOOMbX4aFg==	moErkYEt2v9M1+y+30gv2Q==	a8adMO0swwSh1NwHsIBdqWV8Qpq9WH6glq2IxNFimmg=	lv/84jwWd2eMTAv5ot2YJ9c0q6Az/CtYW4z7y0DW0PVHOtNbFbf36UrzAaE=	LP9YYh7bc5X95WdBVM9ggA==	fWYuTev23gFIod75zVKKRQ==	a80817576f6dfaf0f5c76152d734d9e6a4a7663500146e221d132fc826d4bb38	04576a5fbea5d29ceb562d63a44136847938a729158b270f89a69a993f1d497b1187b5b5ad4b43b2d710ff23e0447496bdad27b61ddbf0b874420f3b2d925cf44a29f865e0cdf98c7d31e89db94640d73601de3e3c26404bbd2052b6114fc73c80cf6a82b309a5367bd626a4fca9059f2053ef39cfd3d164f32dbacc36915d13f8dac7116fe47dcc01e7e3200aefd4ff00c612eea54a659af480e833cbb532e6db46dfab56871209ae65fe6f8d188a0d5bd1ce2f92146502752557af312e09002d3849e61e062e84d1b47634081f8e00e346ffa5263651ea7b598653f3956e04e803d5f5038b1505e7a2f27a337030cee8a48924f7484056d4de344633541e2889815a3fe36d75af44845831c8f400cb8da6a883808d9b078ea1eec8f93b40fa394a93065ad95db450cce5cbcb21966eb11946c23bf0bf9abb6a473de81eae92d84a664f318c1e04ca08bc0d856c6f5ea5f704ee1bd1d51e6ea3da428fac35ff521f908430661352288d7876e0afc5e754dcb77c2f50010c2d888b3e93ee350cd73667e54f7e234a6d17caf2bdffbcbf653e861e2d1b7a29b83b68c092e08bb1012f684cdd0155b68014e13ac11e1d7d8e971a621514fc06d5f4883482467c60a1918554f7d153042804fef8b812ebe6a98b7fa0f1dd1f78be5d6276a232d9119c4f36cdbdd432d742b4b561d154e87e482994ea94798dab1a6274b1711d5890	0c9fba56-8584-4a79-b9ea-183147b9d42e	$2b$12$HYSz/csxzZmyhgx92WfW7OXH/wj47owy668Y8.k.Kpv6hc0uLuJkW	ip560YGEKUcgUvJwDHdZbyFJmPfVJO8gfd2bmduAGs8kXFHzRU97NA7vttM=	XPPH3UWJ0aqJWOXUEa9zXA==	1Bhx5eK0TVPQZUEN+O6XFA==	utf8
a302be16-5e9e-4692-8789-4263feff968f	\N	\N	2	lY8Ktad1ZZbpyhV/tXrCS0r4NqAT7+1gVBAz8nccGlVEDWRfxHNi+x3VMU/IH30eZUuq0OUzOkT291TCUKoDLw==	p+fMYXw6s1TzuSqV	UP55ykwctx4y7rMT2ecwFw==	YFm+DFSIFI5YiIZvKGCbKz669zhZ6RfEbB6+bTfK/Sk=	Kny95QKU8GSlGo+nsm6Y79rOz1puTBJJc1mvkX8kdsNUTYg4Acgmmeldk0A=	k1WrUCs0VseXo5P5	OqHAPpcZC5Ks7K4q93ORAw==	0ef3aa4bb49fef3b49544b04b399ab57c81c4f3341ab541802684277a4a57cd0	5f932a3b51393b2b5490fcd5658d44930d194aaba1050000014734951fd0b0e316de7eafb1b3e2b26616d18639a5fcab647a64b9b0910bf5253bf399b2e28c94fbb3422185129a86a77837169d351a7d2b26c22eb04f72c83203f6bf6c205b2bae4b9b083b2d6d6482b938d0c81b796922d1bfb4f23bd5b517a7c1def4253333aeddc3aad84f72c0f52f9f6ba742c3bb69fffec656d55e3bb38f99097e9ea087a3cfc36709875629d31e119602e525611d6ba556060f86f31bfef5261e687bfbc468b361dbe1bf3f32203da0098adc607370d8d8b832ec318bb59547ea84e711d1be265bcf6c05369b5a475c24e976e17d5dfc1aa5e9e9a836bf26bf40e5f3500776622859877bf96e83e5f39efc5b283c62e1370bb4176de7410eed7b7936129f5bd46116e160ecc67f5b384828277faa7bdb6df8f1f539b696758fb886ba8ec062c26592a3b8ec3e08bf764f226b02499517988b4051dd95821398e8025865c7fb412c36c31c2b41e04390fe6b2b66a575e6ab4496a4a26ed1cf816741ab124c0bc5316dcbf33c3d3afa7329104b788c8f38ed9bdfeaaa28adb54e9881a146a2b829c411afa20b9ceab19c4c76336c911ddc31d180f3ac5d56cc28a4d7d4de7feb9daa687071504be1282ced0395891483854dcc05c54ec166913b36faea51a21ffaa4de5c36262c566d61a108c721fa136758fb08575cca5a8e18d0329f50	f1809a0f-6b04-44bd-84b0-3f61775b693d	\N	\N	\N	\N	\N
e2f317d9-59ff-437e-b5cd-824737da6aba	\N	\N	2	a9Szl0IKgGM7PN3rknloxe1d1V5SLaGrjSVaClpzAdKGxbKQf38ZJH7L6tpJ9TPB6gL7fsnQFE35JHNe1DJTXQ==	O9RHe3bRrgfNasK9	z0oC0yVLzsrQMgt/O524nA==	mYsL2wiKC3Niy7q5RLtmn/U0pfzwO/hZyx4gUbyAO1Y=	WNMW/FSirFp3FGyat5wUmnAOnB+u6iduF+zAt1n7SAYd9hOzwUW5Emy8OUI=	rCbJRiIk1a+7FbBg	bHde/IFstS7Ukw8KCPmIUA==	0a6f0cd929a70812c87dbdd4f4b9a41dfc632fe0d1d532f2ccb92513054efa9d	dbb4146922ca318c21a65a0e4b6f44bdec680eecb87ac2c78c7df4adacd4d9e18e0dd842721fcc17b01d1dd789203a1708b55a1f5656fa1284bfaebdb7527183fc7fd1856dd2bab4e39309fcdf09229b183592d09aef02501a6b1f60a38ba4acf68d57f1cb24b491102495675401ed58fd928a1b768a3193f48d6ad484897bc77c9fc5b9d120dedce2a05ad4026fd3fd515ad54cfd37e77693e6521120f104e56d7bf484cb09df86501ce7786bbe47e26068e70d1bc0f6e34ac3582ecced6817b029913bba81168f20ffd01b72560ca71506dadb4d35a47c7d8ec1c844dd879b8972bbf78a7f08cf14fc06efe0198434f8dc8582014fa32355a56d7b4e8a0cf88ec855925caed0f0d43db2db07e66a9db9c9c17c30bacc62cbb54d536ae2967096be1780c88d2f60dd831337c0fa9552687f15c440b71aa77a2f6bd110d92e686224113937f46113e90b0dafd8e437494c70bec00378d480d57163b3b867a715c8bf476fa8fa37c1664a6eecb49f1282662570ad3ec53058d28559a39e2ed41ed72d9ed36bcd012fd42aee08df1f5299e51761fa2d66cb902df30fe173279f2195e912b5b96f5417f16c95c322ee048d2bed922f99f1674b7749a54ad4b2792a77cb7e2b60c0c3bcb465676e68efcc258c419af0c2ffeee8c55e5daaf55484d5800af3c89be4a1f5f33215dbed62973d250f1728736315cf7c2d4f8619413551	e5826e5e-82bf-41c0-88bc-a0ddb1a28873	\N	\N	\N	\N	\N
50ccc8f4-790e-4046-bd45-f9c4574e8ce4	\N	\N	2	SXpFgqdVbm6h/rXmTXrMKvefSizr9M/fg9rBSGMoN9BDBQT8pBxH5AqUfo2EUg8gk8IrsQDXhdTTUhRcQDO27w==	/RmmWLGSFbaLlx8Y	opnJM7ocynJyITjuFvTitQ==	DAMipcdmv9TuCnwdk0MisElLlFfRZGQZZ4h/gWtnZFw=	1AdrElYtDzgRRgO/Aal3u5bvbA0FYezil+3myX74TE6LzwrCXAFJ5V2J6Es=	MLRaoDChioHe8Muw	EHzJvPT21NBjVikOWCX8Bg==	7267bf74257f383ed95c3447de0afdc1f95681c3dce9da68a10f323b9996c077	eb0949eabb77db62f76a5af4fde0e38c7d24f59f552390756bd4ba881408c29cf7e3c74aca05a30bafada5a948dfeb4b3eadb0fa2269350abb77b961fb49deaea622178464d2244ec61cbb7d537beb43544caacfe080161d6cfef7932e08ac2156767bae07cad6f49cd3953870aa6030b6c457c208e292f07fc492d840e59afbcacb7e476d3453f5593520dc065651a1cb3bc0dc0e5396933d00f2cd5d2a29d1089e1ebd87ee09bf8108f1d15e786c646284756b410ce10e61675efb1e8f21da5db25baff54b0adb55c060461a8ff1b874b169e836636327d38f461e2077ff6dc51dfe31fb5907b373d18da6abf129d94570caa37a26c19f48d467e4fe1d35b3bcbaa651fe46142c66e9ee4d772ea6f0dd5db7f568ce3116adbb70844409eafc24ca6da96adc11aa20a2054ea352ebdf8c19887bb1a848052886e84ea77f222b35b5863c72e8ca535c74afb0205485e674e2fec256702332187657a17f0f3e7fc24e73dd032f3a6d300dc43e71e89167850df1b2f5d3533ef02dfb3c5b4bbdb9425823afdec90b543e3cdd46fb143d6176c203b96497995e9590b83e4c34e00d8dc33ec28b0f9e7b7119a69d40b5c81818a9092ec4131b05d54be24a7a5f9dc787cfc9c4412467282c54a72a69bd64c5cb27ca9c28fd735c01805697f99593da1a8694acab68fcec8a365ce9f8a8660367b4b4a1f70916754294fdeb47d4c167	3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	\N	\N	\N	\N	\N
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.user_group_membership (id, "userId", "groupId", "createdAt", "updatedAt", "isPending") FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.users (id, email, "authMethods", "superAdmin", "firstName", "lastName", "isAccepted", "isMfaEnabled", "mfaMethods", devices, "createdAt", "updatedAt", "isGhost", username, "isEmailVerified", "consecutiveFailedMfaAttempts", "isLocked", "temporaryLockDateEnd", "consecutiveFailedPasswordAttempts") FROM stdin;
f1809a0f-6b04-44bd-84b0-3f61775b693d	sudo-mToogjHfiO9ErFiu-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	{email}	f	\N	\N	t	f	\N	\N	2025-12-10 16:47:32.783881+00	2025-12-10 16:47:32.783881+00	t	sudo-mToogjHfiO9ErFiu-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	f	0	f	\N	0
e5826e5e-82bf-41c0-88bc-a0ddb1a28873	sudo-nM3R8wwOGoGg3mI9-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	{email}	f	\N	\N	t	f	\N	\N	2025-12-10 16:51:43.354054+00	2025-12-10 16:51:43.354054+00	t	sudo-nM3R8wwOGoGg3mI9-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	f	0	f	\N	0
3d856ad0-4a40-4de8-8b41-f1935fcfb6d1	sudo-kGm0v0bsDmHIV5XI-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	{email}	f	\N	\N	t	f	\N	\N	2025-12-16 21:18:33.131298+00	2025-12-16 21:18:33.131298+00	t	sudo-kGm0v0bsDmHIV5XI-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	f	0	f	\N	0
02d439fc-3f86-4889-9792-5cf3bad6f46f	sudo-rZmuxgg9NPqDjDis-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	{email}	f	\N	\N	t	f	\N	\N	2025-10-22 15:34:15.196693+00	2025-10-22 15:34:15.196693+00	t	sudo-rZmuxgg9NPqDjDis-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	f	0	f	\N	0
00155375-154c-4c18-8331-92a36dc7ff1b	rsantamariao@hospitalsantamaria.com.ec	{email}	f	Raul	Santamaria	t	f	\N	[{"ip": "10.42.0.1", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"}, {"ip": "181.39.233.78", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"}]	2025-10-22 15:32:34.310911+00	2025-12-22 20:11:37.38441+00	f	rsantamariao@hospitalsantamaria.com.ec	t	0	f	\N	0
4bbbf546-f610-4234-ad37-1c3c72f95747	sudo-VoNcEipp3bZBeseg-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	{email}	f	\N	\N	t	f	\N	\N	2025-11-11 19:17:01.616918+00	2025-11-11 19:17:01.616918+00	t	sudo-VoNcEipp3bZBeseg-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	f	0	f	\N	0
af0d16ce-271a-485e-81ae-37d56c4d8571	sudo-H8sxpFQibSWLtAgv-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	{email}	f	\N	\N	t	f	\N	\N	2025-12-08 17:38:56.347493+00	2025-12-08 17:38:56.347493+00	t	sudo-H8sxpFQibSWLtAgv-c487807e-8e63-4847-8e80-12bdf173b280@infisical.com	f	0	f	\N	0
0c9fba56-8584-4a79-b9ea-183147b9d42e	raulsantamariao@hotmail.com	{github,email}	t	Raul	Santamaria	t	f	\N	[{"ip": "10.42.0.1", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"}, {"ip": "10.42.0.1", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"}, {"ip": "10.42.0.1", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"}, {"ip": "186.68.104.126", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"}, {"ip": "10.42.1.0", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"}, {"ip": "10.42.1.1", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"}, {"ip": "181.39.233.78", "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"}, {"ip": "181.39.233.78", "userAgent": "cli"}]	2025-10-22 15:25:08.234533+00	2025-12-23 19:00:06.962666+00	f	raulsantamariao@hotmail.com	t	0	f	\N	0
\.


--
-- Data for Name: webhooks; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.webhooks (id, "secretPath", url, "lastStatus", "lastRunErrorMessage", "isDisabled", "encryptedSecretKey", iv, tag, algorithm, "keyEncoding", "createdAt", "updatedAt", "envId", "urlCipherText", "urlIV", "urlTag", type) FROM stdin;
\.


--
-- Data for Name: workflow_integrations; Type: TABLE DATA; Schema: public; Owner: infisical
--

COPY public.workflow_integrations (id, integration, slug, "orgId", description, "createdAt", "updatedAt") FROM stdin;
\.


--
-- Name: infisical_migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: infisical
--

SELECT pg_catalog.setval('public.infisical_migrations_id_seq', 135, true);


--
-- Name: infisical_migrations_lock_index_seq; Type: SEQUENCE SET; Schema: public; Owner: infisical
--

SELECT pg_catalog.setval('public.infisical_migrations_lock_index_seq', 1, true);


--
-- Name: access_approval_policies_approvers access_approval_policies_approvers_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_policies_approvers
    ADD CONSTRAINT access_approval_policies_approvers_pkey PRIMARY KEY (id);


--
-- Name: access_approval_policies access_approval_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_policies
    ADD CONSTRAINT access_approval_policies_pkey PRIMARY KEY (id);


--
-- Name: access_approval_requests access_approval_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests
    ADD CONSTRAINT access_approval_requests_pkey PRIMARY KEY (id);


--
-- Name: access_approval_requests_reviewers access_approval_requests_reviewers_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests_reviewers
    ADD CONSTRAINT access_approval_requests_reviewers_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: audit_log_streams audit_log_streams_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.audit_log_streams
    ADD CONSTRAINT audit_log_streams_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: auth_token_sessions auth_token_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.auth_token_sessions
    ADD CONSTRAINT auth_token_sessions_pkey PRIMARY KEY (id);


--
-- Name: auth_tokens auth_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_pkey PRIMARY KEY (id);


--
-- Name: backup_private_key backup_private_key_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.backup_private_key
    ADD CONSTRAINT backup_private_key_pkey PRIMARY KEY (id);


--
-- Name: backup_private_key backup_private_key_userid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.backup_private_key
    ADD CONSTRAINT backup_private_key_userid_unique UNIQUE ("userId");


--
-- Name: certificate_authorities certificate_authorities_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_pkey PRIMARY KEY (id);


--
-- Name: certificate_authorities certificate_authorities_serialnumber_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_serialnumber_unique UNIQUE ("serialNumber");


--
-- Name: certificate_authority_certs certificate_authority_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_certs
    ADD CONSTRAINT certificate_authority_certs_pkey PRIMARY KEY (id);


--
-- Name: certificate_authority_crl certificate_authority_crl_caid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_crl
    ADD CONSTRAINT certificate_authority_crl_caid_unique UNIQUE ("caId");


--
-- Name: certificate_authority_crl certificate_authority_crl_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_crl
    ADD CONSTRAINT certificate_authority_crl_pkey PRIMARY KEY (id);


--
-- Name: certificate_authority_secret certificate_authority_secret_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_secret
    ADD CONSTRAINT certificate_authority_secret_pkey PRIMARY KEY (id);


--
-- Name: certificate_bodies certificate_bodies_certid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_bodies
    ADD CONSTRAINT certificate_bodies_certid_unique UNIQUE ("certId");


--
-- Name: certificate_bodies certificate_bodies_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_bodies
    ADD CONSTRAINT certificate_bodies_pkey PRIMARY KEY (id);


--
-- Name: certificate_template_est_configs certificate_template_est_configs_certificatetemplateid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_template_est_configs
    ADD CONSTRAINT certificate_template_est_configs_certificatetemplateid_unique UNIQUE ("certificateTemplateId");


--
-- Name: certificate_template_est_configs certificate_template_est_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_template_est_configs
    ADD CONSTRAINT certificate_template_est_configs_pkey PRIMARY KEY (id);


--
-- Name: certificate_templates certificate_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_templates
    ADD CONSTRAINT certificate_templates_pkey PRIMARY KEY (id);


--
-- Name: certificates certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);


--
-- Name: certificates certificates_serialnumber_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_serialnumber_unique UNIQUE ("serialNumber");


--
-- Name: dynamic_secret_leases dynamic_secret_leases_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.dynamic_secret_leases
    ADD CONSTRAINT dynamic_secret_leases_pkey PRIMARY KEY (id);


--
-- Name: dynamic_secrets dynamic_secrets_name_folderid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.dynamic_secrets
    ADD CONSTRAINT dynamic_secrets_name_folderid_unique UNIQUE (name, "folderId");


--
-- Name: dynamic_secrets dynamic_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.dynamic_secrets
    ADD CONSTRAINT dynamic_secrets_pkey PRIMARY KEY (id);


--
-- Name: project_environments env_pos_composite_uniqe; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_environments
    ADD CONSTRAINT env_pos_composite_uniqe UNIQUE ("projectId", "position") DEFERRABLE INITIALLY DEFERRED;


--
-- Name: external_group_org_role_mappings external_group_org_role_mappings_orgid_groupname_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.external_group_org_role_mappings
    ADD CONSTRAINT external_group_org_role_mappings_orgid_groupname_unique UNIQUE ("orgId", "groupName");


--
-- Name: external_group_org_role_mappings external_group_org_role_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.external_group_org_role_mappings
    ADD CONSTRAINT external_group_org_role_mappings_pkey PRIMARY KEY (id);


--
-- Name: external_kms external_kms_kmskeyid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.external_kms
    ADD CONSTRAINT external_kms_kmskeyid_unique UNIQUE ("kmsKeyId");


--
-- Name: external_kms external_kms_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.external_kms
    ADD CONSTRAINT external_kms_pkey PRIMARY KEY (id);


--
-- Name: git_app_install_sessions git_app_install_sessions_orgid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_install_sessions
    ADD CONSTRAINT git_app_install_sessions_orgid_unique UNIQUE ("orgId");


--
-- Name: git_app_install_sessions git_app_install_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_install_sessions
    ADD CONSTRAINT git_app_install_sessions_pkey PRIMARY KEY (id);


--
-- Name: git_app_install_sessions git_app_install_sessions_sessionid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_install_sessions
    ADD CONSTRAINT git_app_install_sessions_sessionid_unique UNIQUE ("sessionId");


--
-- Name: git_app_org git_app_org_installationid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_org
    ADD CONSTRAINT git_app_org_installationid_unique UNIQUE ("installationId");


--
-- Name: git_app_org git_app_org_orgid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_org
    ADD CONSTRAINT git_app_org_orgid_unique UNIQUE ("orgId");


--
-- Name: git_app_org git_app_org_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_org
    ADD CONSTRAINT git_app_org_pkey PRIMARY KEY (id);


--
-- Name: group_project_membership_roles group_project_membership_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.group_project_membership_roles
    ADD CONSTRAINT group_project_membership_roles_pkey PRIMARY KEY (id);


--
-- Name: group_project_memberships group_project_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.group_project_memberships
    ADD CONSTRAINT group_project_memberships_pkey PRIMARY KEY (id);


--
-- Name: groups groups_orgid_slug_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_orgid_slug_unique UNIQUE ("orgId", slug);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: identities identities_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identities
    ADD CONSTRAINT identities_pkey PRIMARY KEY (id);


--
-- Name: identity_access_tokens identity_access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_access_tokens
    ADD CONSTRAINT identity_access_tokens_pkey PRIMARY KEY (id);


--
-- Name: identity_aws_auths identity_aws_auths_identityid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_aws_auths
    ADD CONSTRAINT identity_aws_auths_identityid_unique UNIQUE ("identityId");


--
-- Name: identity_aws_auths identity_aws_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_aws_auths
    ADD CONSTRAINT identity_aws_auths_pkey PRIMARY KEY (id);


--
-- Name: identity_azure_auths identity_azure_auths_identityid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_azure_auths
    ADD CONSTRAINT identity_azure_auths_identityid_unique UNIQUE ("identityId");


--
-- Name: identity_azure_auths identity_azure_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_azure_auths
    ADD CONSTRAINT identity_azure_auths_pkey PRIMARY KEY (id);


--
-- Name: identity_gcp_auths identity_gcp_auths_identityid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_gcp_auths
    ADD CONSTRAINT identity_gcp_auths_identityid_unique UNIQUE ("identityId");


--
-- Name: identity_gcp_auths identity_gcp_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_gcp_auths
    ADD CONSTRAINT identity_gcp_auths_pkey PRIMARY KEY (id);


--
-- Name: identity_kubernetes_auths identity_kubernetes_auths_identityid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_kubernetes_auths
    ADD CONSTRAINT identity_kubernetes_auths_identityid_unique UNIQUE ("identityId");


--
-- Name: identity_kubernetes_auths identity_kubernetes_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_kubernetes_auths
    ADD CONSTRAINT identity_kubernetes_auths_pkey PRIMARY KEY (id);


--
-- Name: identity_metadata identity_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_metadata
    ADD CONSTRAINT identity_metadata_pkey PRIMARY KEY (id);


--
-- Name: identity_oidc_auths identity_oidc_auths_identityid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_oidc_auths
    ADD CONSTRAINT identity_oidc_auths_identityid_unique UNIQUE ("identityId");


--
-- Name: identity_oidc_auths identity_oidc_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_oidc_auths
    ADD CONSTRAINT identity_oidc_auths_pkey PRIMARY KEY (id);


--
-- Name: identity_org_memberships identity_org_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_org_memberships
    ADD CONSTRAINT identity_org_memberships_pkey PRIMARY KEY (id);


--
-- Name: identity_project_additional_privilege identity_project_additional_privilege_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_additional_privilege
    ADD CONSTRAINT identity_project_additional_privilege_pkey PRIMARY KEY (id);


--
-- Name: identity_project_membership_role identity_project_membership_role_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_membership_role
    ADD CONSTRAINT identity_project_membership_role_pkey PRIMARY KEY (id);


--
-- Name: identity_project_memberships identity_project_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_memberships
    ADD CONSTRAINT identity_project_memberships_pkey PRIMARY KEY (id);


--
-- Name: identity_token_auths identity_token_auths_identityid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_token_auths
    ADD CONSTRAINT identity_token_auths_identityid_unique UNIQUE ("identityId");


--
-- Name: identity_token_auths identity_token_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_token_auths
    ADD CONSTRAINT identity_token_auths_pkey PRIMARY KEY (id);


--
-- Name: identity_ua_client_secrets identity_ua_client_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_ua_client_secrets
    ADD CONSTRAINT identity_ua_client_secrets_pkey PRIMARY KEY (id);


--
-- Name: identity_universal_auths identity_universal_auths_identityid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_universal_auths
    ADD CONSTRAINT identity_universal_auths_identityid_unique UNIQUE ("identityId");


--
-- Name: identity_universal_auths identity_universal_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_universal_auths
    ADD CONSTRAINT identity_universal_auths_pkey PRIMARY KEY (id);


--
-- Name: secret_imports import_pos_composite_uniqe; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_imports
    ADD CONSTRAINT import_pos_composite_uniqe UNIQUE ("folderId", "position") DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_contacts incident_contacts_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.incident_contacts
    ADD CONSTRAINT incident_contacts_pkey PRIMARY KEY (id);


--
-- Name: infisical_migrations_lock infisical_migrations_lock_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.infisical_migrations_lock
    ADD CONSTRAINT infisical_migrations_lock_pkey PRIMARY KEY (index);


--
-- Name: infisical_migrations infisical_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.infisical_migrations
    ADD CONSTRAINT infisical_migrations_pkey PRIMARY KEY (id);


--
-- Name: integration_auths integration_auths_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.integration_auths
    ADD CONSTRAINT integration_auths_pkey PRIMARY KEY (id);


--
-- Name: integrations integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_pkey PRIMARY KEY (id);


--
-- Name: internal_kms internal_kms_kmskeyid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.internal_kms
    ADD CONSTRAINT internal_kms_kmskeyid_unique UNIQUE ("kmsKeyId");


--
-- Name: internal_kms internal_kms_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.internal_kms
    ADD CONSTRAINT internal_kms_pkey PRIMARY KEY (id);


--
-- Name: internal_kms_key_version kms_key_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.internal_kms_key_version
    ADD CONSTRAINT kms_key_versions_pkey PRIMARY KEY (id);


--
-- Name: kms_keys kms_keys_orgid_projectid_slug_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.kms_keys
    ADD CONSTRAINT kms_keys_orgid_projectid_slug_unique UNIQUE ("orgId", "projectId", name);


--
-- Name: kms_keys kms_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.kms_keys
    ADD CONSTRAINT kms_keys_pkey PRIMARY KEY (id);


--
-- Name: kms_root_config kms_root_config_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.kms_root_config
    ADD CONSTRAINT kms_root_config_pkey PRIMARY KEY (id);


--
-- Name: ldap_configs ldap_configs_orgid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.ldap_configs
    ADD CONSTRAINT ldap_configs_orgid_unique UNIQUE ("orgId");


--
-- Name: ldap_configs ldap_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.ldap_configs
    ADD CONSTRAINT ldap_configs_pkey PRIMARY KEY (id);


--
-- Name: ldap_group_maps ldap_group_maps_ldapgroupcn_groupid_ldapconfigid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.ldap_group_maps
    ADD CONSTRAINT ldap_group_maps_ldapgroupcn_groupid_ldapconfigid_unique UNIQUE ("ldapGroupCN", "groupId", "ldapConfigId");


--
-- Name: ldap_group_maps ldap_group_maps_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.ldap_group_maps
    ADD CONSTRAINT ldap_group_maps_pkey PRIMARY KEY (id);


--
-- Name: oidc_configs oidc_configs_orgid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.oidc_configs
    ADD CONSTRAINT oidc_configs_orgid_unique UNIQUE ("orgId");


--
-- Name: oidc_configs oidc_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.oidc_configs
    ADD CONSTRAINT oidc_configs_pkey PRIMARY KEY (id);


--
-- Name: org_bots org_bots_orgid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_bots
    ADD CONSTRAINT org_bots_orgid_unique UNIQUE ("orgId");


--
-- Name: org_bots org_bots_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_bots
    ADD CONSTRAINT org_bots_pkey PRIMARY KEY (id);


--
-- Name: org_memberships org_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_pkey PRIMARY KEY (id);


--
-- Name: org_memberships org_memberships_userid_orgid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_userid_orgid_unique UNIQUE ("userId", "orgId");


--
-- Name: org_roles org_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_roles
    ADD CONSTRAINT org_roles_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_slug_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_slug_unique UNIQUE (slug);


--
-- Name: pki_alerts pki_alerts_name_projectid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_alerts
    ADD CONSTRAINT pki_alerts_name_projectid_unique UNIQUE (name, "projectId");


--
-- Name: pki_alerts pki_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_alerts
    ADD CONSTRAINT pki_alerts_pkey PRIMARY KEY (id);


--
-- Name: pki_collection_items pki_collection_items_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_collection_items
    ADD CONSTRAINT pki_collection_items_pkey PRIMARY KEY (id);


--
-- Name: pki_collections pki_collections_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_collections
    ADD CONSTRAINT pki_collections_pkey PRIMARY KEY (id);


--
-- Name: project_bots project_bots_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_bots
    ADD CONSTRAINT project_bots_pkey PRIMARY KEY (id);


--
-- Name: project_bots project_bots_projectid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_bots
    ADD CONSTRAINT project_bots_projectid_unique UNIQUE ("projectId");


--
-- Name: project_environments project_environments_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_environments
    ADD CONSTRAINT project_environments_pkey PRIMARY KEY (id);


--
-- Name: project_keys project_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_keys
    ADD CONSTRAINT project_keys_pkey PRIMARY KEY (id);


--
-- Name: project_memberships project_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_memberships
    ADD CONSTRAINT project_memberships_pkey PRIMARY KEY (id);


--
-- Name: project_roles project_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_roles
    ADD CONSTRAINT project_roles_pkey PRIMARY KEY (id);


--
-- Name: project_slack_configs project_slack_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_slack_configs
    ADD CONSTRAINT project_slack_configs_pkey PRIMARY KEY (id);


--
-- Name: project_slack_configs project_slack_configs_projectid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_slack_configs
    ADD CONSTRAINT project_slack_configs_projectid_unique UNIQUE ("projectId");


--
-- Name: project_user_additional_privilege project_user_additional_privilege_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_user_additional_privilege
    ADD CONSTRAINT project_user_additional_privilege_pkey PRIMARY KEY (id);


--
-- Name: project_user_membership_roles project_user_membership_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_user_membership_roles
    ADD CONSTRAINT project_user_membership_roles_pkey PRIMARY KEY (id);


--
-- Name: projects projects_orgid_slug_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_orgid_slug_unique UNIQUE ("orgId", slug);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: rate_limit rate_limit_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.rate_limit
    ADD CONSTRAINT rate_limit_pkey PRIMARY KEY (id);


--
-- Name: saml_configs saml_configs_orgid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.saml_configs
    ADD CONSTRAINT saml_configs_orgid_unique UNIQUE ("orgId");


--
-- Name: saml_configs saml_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.saml_configs
    ADD CONSTRAINT saml_configs_pkey PRIMARY KEY (id);


--
-- Name: scim_tokens scim_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_policies_approvers secret_approval_policies_approvers_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_policies_approvers
    ADD CONSTRAINT secret_approval_policies_approvers_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_policies secret_approval_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_policies
    ADD CONSTRAINT secret_approval_policies_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_request_secret_tags secret_approval_request_secret_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_request_secret_tags
    ADD CONSTRAINT secret_approval_request_secret_tags_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_request_secret_tags_v2 secret_approval_request_secret_tags_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_request_secret_tags_v2
    ADD CONSTRAINT secret_approval_request_secret_tags_v2_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_requests secret_approval_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests
    ADD CONSTRAINT secret_approval_requests_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_requests_reviewers secret_approval_requests_reviewers_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_reviewers
    ADD CONSTRAINT secret_approval_requests_reviewers_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_requests_secrets secret_approval_requests_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets
    ADD CONSTRAINT secret_approval_requests_secrets_pkey PRIMARY KEY (id);


--
-- Name: secret_approval_requests_secrets_v2 secret_approval_requests_secrets_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets_v2
    ADD CONSTRAINT secret_approval_requests_secrets_v2_pkey PRIMARY KEY (id);


--
-- Name: secret_blind_indexes secret_blind_indexes_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_blind_indexes
    ADD CONSTRAINT secret_blind_indexes_pkey PRIMARY KEY (id);


--
-- Name: secret_blind_indexes secret_blind_indexes_projectid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_blind_indexes
    ADD CONSTRAINT secret_blind_indexes_projectid_unique UNIQUE ("projectId");


--
-- Name: secret_folder_versions secret_folder_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_folder_versions
    ADD CONSTRAINT secret_folder_versions_pkey PRIMARY KEY (id);


--
-- Name: secret_folders secret_folders_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_folders
    ADD CONSTRAINT secret_folders_pkey PRIMARY KEY (id);


--
-- Name: secret_imports secret_imports_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_imports
    ADD CONSTRAINT secret_imports_pkey PRIMARY KEY (id);


--
-- Name: secret_references secret_references_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_references
    ADD CONSTRAINT secret_references_pkey PRIMARY KEY (id);


--
-- Name: secret_references_v2 secret_references_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_references_v2
    ADD CONSTRAINT secret_references_v2_pkey PRIMARY KEY (id);


--
-- Name: secret_rotation_output_v2 secret_rotation_output_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotation_output_v2
    ADD CONSTRAINT secret_rotation_output_v2_pkey PRIMARY KEY (id);


--
-- Name: secret_rotation_outputs secret_rotation_outputs_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotation_outputs
    ADD CONSTRAINT secret_rotation_outputs_pkey PRIMARY KEY (id);


--
-- Name: secret_rotations secret_rotations_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotations
    ADD CONSTRAINT secret_rotations_pkey PRIMARY KEY (id);


--
-- Name: secret_scanning_git_risks secret_scanning_git_risks_fingerprint_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_scanning_git_risks
    ADD CONSTRAINT secret_scanning_git_risks_fingerprint_unique UNIQUE (fingerprint);


--
-- Name: secret_scanning_git_risks secret_scanning_git_risks_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_scanning_git_risks
    ADD CONSTRAINT secret_scanning_git_risks_pkey PRIMARY KEY (id);


--
-- Name: secret_sharing secret_sharing_identifier_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_sharing
    ADD CONSTRAINT secret_sharing_identifier_unique UNIQUE (identifier);


--
-- Name: secret_sharing secret_sharing_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_sharing
    ADD CONSTRAINT secret_sharing_pkey PRIMARY KEY (id);


--
-- Name: secret_snapshot_folders secret_snapshot_folders_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_folders
    ADD CONSTRAINT secret_snapshot_folders_pkey PRIMARY KEY (id);


--
-- Name: secret_snapshot_secrets secret_snapshot_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets
    ADD CONSTRAINT secret_snapshot_secrets_pkey PRIMARY KEY (id);


--
-- Name: secret_snapshot_secrets_v2 secret_snapshot_secrets_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets_v2
    ADD CONSTRAINT secret_snapshot_secrets_v2_pkey PRIMARY KEY (id);


--
-- Name: secret_snapshots secret_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshots
    ADD CONSTRAINT secret_snapshots_pkey PRIMARY KEY (id);


--
-- Name: secret_tag_junction secret_tag_junction_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_tag_junction
    ADD CONSTRAINT secret_tag_junction_pkey PRIMARY KEY (id);


--
-- Name: secret_tags secret_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_tags
    ADD CONSTRAINT secret_tags_pkey PRIMARY KEY (id);


--
-- Name: secret_v2_tag_junction secret_v2_tag_junction_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_v2_tag_junction
    ADD CONSTRAINT secret_v2_tag_junction_pkey PRIMARY KEY (id);


--
-- Name: secret_version_tag_junction secret_version_tag_junction_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_version_tag_junction
    ADD CONSTRAINT secret_version_tag_junction_pkey PRIMARY KEY (id);


--
-- Name: secret_version_v2_tag_junction secret_version_v2_tag_junction_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_version_v2_tag_junction
    ADD CONSTRAINT secret_version_v2_tag_junction_pkey PRIMARY KEY (id);


--
-- Name: secret_versions secret_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_pkey PRIMARY KEY (id);


--
-- Name: secret_versions_v2 secret_versions_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_versions_v2
    ADD CONSTRAINT secret_versions_v2_pkey PRIMARY KEY (id);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: secrets_v2 secrets_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secrets_v2
    ADD CONSTRAINT secrets_v2_pkey PRIMARY KEY (id);


--
-- Name: service_tokens service_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.service_tokens
    ADD CONSTRAINT service_tokens_pkey PRIMARY KEY (id);


--
-- Name: slack_integrations slack_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.slack_integrations
    ADD CONSTRAINT slack_integrations_pkey PRIMARY KEY (id);


--
-- Name: super_admin super_admin_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.super_admin
    ADD CONSTRAINT super_admin_pkey PRIMARY KEY (id);


--
-- Name: trusted_ips trusted_ips_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.trusted_ips
    ADD CONSTRAINT trusted_ips_pkey PRIMARY KEY (id);


--
-- Name: user_actions user_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_actions
    ADD CONSTRAINT user_actions_pkey PRIMARY KEY (id);


--
-- Name: user_aliases user_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_aliases
    ADD CONSTRAINT user_aliases_pkey PRIMARY KEY (id);


--
-- Name: user_encryption_keys user_encryption_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_encryption_keys
    ADD CONSTRAINT user_encryption_keys_pkey PRIMARY KEY (id);


--
-- Name: user_encryption_keys user_encryption_keys_userid_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_encryption_keys
    ADD CONSTRAINT user_encryption_keys_userid_unique UNIQUE ("userId");


--
-- Name: user_group_membership user_group_membership_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT user_group_membership_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_unique UNIQUE (username);


--
-- Name: webhooks webhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_pkey PRIMARY KEY (id);


--
-- Name: workflow_integrations workflow_integrations_orgid_slug_unique; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.workflow_integrations
    ADD CONSTRAINT workflow_integrations_orgid_slug_unique UNIQUE ("orgId", slug);


--
-- Name: workflow_integrations workflow_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.workflow_integrations
    ADD CONSTRAINT workflow_integrations_pkey PRIMARY KEY (id);


--
-- Name: audit_logs_expiresat_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX audit_logs_expiresat_index ON public.audit_logs USING btree ("expiresAt");


--
-- Name: audit_logs_orgid_createdat_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX audit_logs_orgid_createdat_index ON public.audit_logs USING btree ("orgId", "createdAt");


--
-- Name: audit_logs_orgid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX audit_logs_orgid_index ON public.audit_logs USING btree ("orgId");


--
-- Name: audit_logs_projectid_createdat_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX audit_logs_projectid_createdat_index ON public.audit_logs USING btree ("projectId", "createdAt");


--
-- Name: audit_logs_projectid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX audit_logs_projectid_index ON public.audit_logs USING btree ("projectId");


--
-- Name: external_group_org_role_mappings_groupname_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX external_group_org_role_mappings_groupname_index ON public.external_group_org_role_mappings USING btree ("groupName");


--
-- Name: org_memberships_userid_orgid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX org_memberships_userid_orgid_index ON public.org_memberships USING btree ("userId", "orgId");


--
-- Name: organizations_slug_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX organizations_slug_index ON public.organizations USING btree (slug);


--
-- Name: secret_sharing_identifier_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_sharing_identifier_index ON public.secret_sharing USING btree (identifier);


--
-- Name: secret_snapshot_folders_snapshotid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_snapshot_folders_snapshotid_index ON public.secret_snapshot_folders USING btree ("snapshotId");


--
-- Name: secret_snapshot_secrets_envid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_snapshot_secrets_envid_index ON public.secret_snapshot_secrets USING btree ("envId");


--
-- Name: secret_snapshot_secrets_secretversionid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_snapshot_secrets_secretversionid_index ON public.secret_snapshot_secrets USING btree ("secretVersionId");


--
-- Name: secret_snapshot_secrets_snapshotid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_snapshot_secrets_snapshotid_index ON public.secret_snapshot_secrets USING btree ("snapshotId");


--
-- Name: secret_snapshot_secrets_v2_envid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_snapshot_secrets_v2_envid_index ON public.secret_snapshot_secrets_v2 USING btree ("envId");


--
-- Name: secret_snapshot_secrets_v2_secretversionid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_snapshot_secrets_v2_secretversionid_index ON public.secret_snapshot_secrets_v2 USING btree ("secretVersionId");


--
-- Name: secret_snapshot_secrets_v2_snapshotid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_snapshot_secrets_v2_snapshotid_index ON public.secret_snapshot_secrets_v2 USING btree ("snapshotId");


--
-- Name: secret_versions_envid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secret_versions_envid_index ON public.secret_versions USING btree ("envId");


--
-- Name: secrets_folderid_userid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secrets_folderid_userid_index ON public.secrets USING btree ("folderId", "userId");


--
-- Name: secrets_secretblindindex_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secrets_secretblindindex_index ON public.secrets USING btree ("secretBlindIndex");


--
-- Name: secrets_v2_folderid_userid_index; Type: INDEX; Schema: public; Owner: infisical
--

CREATE INDEX secrets_v2_folderid_userid_index ON public.secrets_v2 USING btree ("folderId", "userId");


--
-- Name: access_approval_policies_approvers access_approval_policies_approvers_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "access_approval_policies_approvers_updatedAt" BEFORE UPDATE ON public.access_approval_policies_approvers FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: access_approval_policies access_approval_policies_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "access_approval_policies_updatedAt" BEFORE UPDATE ON public.access_approval_policies FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: access_approval_requests_reviewers access_approval_requests_reviewers_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "access_approval_requests_reviewers_updatedAt" BEFORE UPDATE ON public.access_approval_requests_reviewers FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: access_approval_requests access_approval_requests_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "access_approval_requests_updatedAt" BEFORE UPDATE ON public.access_approval_requests FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: api_keys api_keys_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "api_keys_updatedAt" BEFORE UPDATE ON public.api_keys FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: audit_log_streams audit_log_streams_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "audit_log_streams_updatedAt" BEFORE UPDATE ON public.audit_log_streams FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: auth_token_sessions auth_token_sessions_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "auth_token_sessions_updatedAt" BEFORE UPDATE ON public.auth_token_sessions FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: certificate_authorities certificate_authorities_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "certificate_authorities_updatedAt" BEFORE UPDATE ON public.certificate_authorities FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: certificate_authority_certs certificate_authority_certs_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "certificate_authority_certs_updatedAt" BEFORE UPDATE ON public.certificate_authority_certs FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: certificate_authority_secret certificate_authority_secret_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "certificate_authority_secret_updatedAt" BEFORE UPDATE ON public.certificate_authority_secret FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: certificate_bodies certificate_bodies_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "certificate_bodies_updatedAt" BEFORE UPDATE ON public.certificate_bodies FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: certificate_template_est_configs certificate_template_est_configs_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "certificate_template_est_configs_updatedAt" BEFORE UPDATE ON public.certificate_template_est_configs FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: certificate_templates certificate_templates_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "certificate_templates_updatedAt" BEFORE UPDATE ON public.certificate_templates FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: certificates certificates_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "certificates_updatedAt" BEFORE UPDATE ON public.certificates FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: dynamic_secret_leases dynamic_secret_leases_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "dynamic_secret_leases_updatedAt" BEFORE UPDATE ON public.dynamic_secret_leases FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: dynamic_secrets dynamic_secrets_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "dynamic_secrets_updatedAt" BEFORE UPDATE ON public.dynamic_secrets FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: external_group_org_role_mappings external_group_org_role_mappings_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "external_group_org_role_mappings_updatedAt" BEFORE UPDATE ON public.external_group_org_role_mappings FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: git_app_install_sessions git_app_install_sessions_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "git_app_install_sessions_updatedAt" BEFORE UPDATE ON public.git_app_install_sessions FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: git_app_org git_app_org_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "git_app_org_updatedAt" BEFORE UPDATE ON public.git_app_org FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: group_project_membership_roles group_project_membership_roles_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "group_project_membership_roles_updatedAt" BEFORE UPDATE ON public.group_project_membership_roles FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: group_project_memberships group_project_memberships_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "group_project_memberships_updatedAt" BEFORE UPDATE ON public.group_project_memberships FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: groups groups_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "groups_updatedAt" BEFORE UPDATE ON public.groups FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identities identities_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identities_updatedAt" BEFORE UPDATE ON public.identities FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_access_tokens identity_access_tokens_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_access_tokens_updatedAt" BEFORE UPDATE ON public.identity_access_tokens FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_aws_auths identity_aws_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_aws_auths_updatedAt" BEFORE UPDATE ON public.identity_aws_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_azure_auths identity_azure_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_azure_auths_updatedAt" BEFORE UPDATE ON public.identity_azure_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_gcp_auths identity_gcp_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_gcp_auths_updatedAt" BEFORE UPDATE ON public.identity_gcp_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_kubernetes_auths identity_kubernetes_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_kubernetes_auths_updatedAt" BEFORE UPDATE ON public.identity_kubernetes_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_oidc_auths identity_oidc_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_oidc_auths_updatedAt" BEFORE UPDATE ON public.identity_oidc_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_org_memberships identity_org_memberships_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_org_memberships_updatedAt" BEFORE UPDATE ON public.identity_org_memberships FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_project_additional_privilege identity_project_additional_privilege_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_project_additional_privilege_updatedAt" BEFORE UPDATE ON public.identity_project_additional_privilege FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_project_membership_role identity_project_membership_role_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_project_membership_role_updatedAt" BEFORE UPDATE ON public.identity_project_membership_role FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_project_memberships identity_project_memberships_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_project_memberships_updatedAt" BEFORE UPDATE ON public.identity_project_memberships FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_token_auths identity_token_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_token_auths_updatedAt" BEFORE UPDATE ON public.identity_token_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_ua_client_secrets identity_ua_client_secrets_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_ua_client_secrets_updatedAt" BEFORE UPDATE ON public.identity_ua_client_secrets FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: identity_universal_auths identity_universal_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "identity_universal_auths_updatedAt" BEFORE UPDATE ON public.identity_universal_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: incident_contacts incident_contacts_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "incident_contacts_updatedAt" BEFORE UPDATE ON public.incident_contacts FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: integration_auths integration_auths_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "integration_auths_updatedAt" BEFORE UPDATE ON public.integration_auths FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: integrations integrations_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "integrations_updatedAt" BEFORE UPDATE ON public.integrations FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: internal_kms_key_version kms_key_versions_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "kms_key_versions_updatedAt" BEFORE UPDATE ON public.internal_kms_key_version FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: kms_keys kms_keys_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "kms_keys_updatedAt" BEFORE UPDATE ON public.kms_keys FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: kms_root_config kms_root_config_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "kms_root_config_updatedAt" BEFORE UPDATE ON public.kms_root_config FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: ldap_configs ldap_configs_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "ldap_configs_updatedAt" BEFORE UPDATE ON public.ldap_configs FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: ldap_group_maps ldap_group_maps_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "ldap_group_maps_updatedAt" BEFORE UPDATE ON public.ldap_group_maps FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: oidc_configs oidc_configs_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "oidc_configs_updatedAt" BEFORE UPDATE ON public.oidc_configs FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: org_bots org_bots_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "org_bots_updatedAt" BEFORE UPDATE ON public.org_bots FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: org_memberships org_memberships_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "org_memberships_updatedAt" BEFORE UPDATE ON public.org_memberships FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: organizations organizations_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "organizations_updatedAt" BEFORE UPDATE ON public.organizations FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: pki_alerts pki_alerts_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "pki_alerts_updatedAt" BEFORE UPDATE ON public.pki_alerts FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: pki_collection_items pki_collection_items_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "pki_collection_items_updatedAt" BEFORE UPDATE ON public.pki_collection_items FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: pki_collections pki_collections_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "pki_collections_updatedAt" BEFORE UPDATE ON public.pki_collections FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: project_bots project_bots_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "project_bots_updatedAt" BEFORE UPDATE ON public.project_bots FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: project_keys project_keys_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "project_keys_updatedAt" BEFORE UPDATE ON public.project_keys FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: project_memberships project_memberships_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "project_memberships_updatedAt" BEFORE UPDATE ON public.project_memberships FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: project_slack_configs project_slack_configs_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "project_slack_configs_updatedAt" BEFORE UPDATE ON public.project_slack_configs FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: project_user_additional_privilege project_user_additional_privilege_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "project_user_additional_privilege_updatedAt" BEFORE UPDATE ON public.project_user_additional_privilege FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: project_user_membership_roles project_user_membership_roles_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "project_user_membership_roles_updatedAt" BEFORE UPDATE ON public.project_user_membership_roles FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: projects projects_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "projects_updatedAt" BEFORE UPDATE ON public.projects FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: rate_limit rate_limit_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "rate_limit_updatedAt" BEFORE UPDATE ON public.rate_limit FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: saml_configs saml_configs_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "saml_configs_updatedAt" BEFORE UPDATE ON public.saml_configs FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: scim_tokens scim_tokens_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "scim_tokens_updatedAt" BEFORE UPDATE ON public.scim_tokens FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_approval_policies_approvers secret_approval_policies_approvers_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_approval_policies_approvers_updatedAt" BEFORE UPDATE ON public.secret_approval_policies_approvers FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_approval_policies secret_approval_policies_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_approval_policies_updatedAt" BEFORE UPDATE ON public.secret_approval_policies FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_approval_request_secret_tags secret_approval_request_secret_tags_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_approval_request_secret_tags_updatedAt" BEFORE UPDATE ON public.secret_approval_request_secret_tags FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_approval_requests_reviewers secret_approval_requests_reviewers_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_approval_requests_reviewers_updatedAt" BEFORE UPDATE ON public.secret_approval_requests_reviewers FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_approval_requests_secrets secret_approval_requests_secrets_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_approval_requests_secrets_updatedAt" BEFORE UPDATE ON public.secret_approval_requests_secrets FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_approval_requests secret_approval_requests_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_approval_requests_updatedAt" BEFORE UPDATE ON public.secret_approval_requests FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_blind_indexes secret_blind_indexes_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_blind_indexes_updatedAt" BEFORE UPDATE ON public.secret_blind_indexes FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_folder_versions secret_folder_versions_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_folder_versions_updatedAt" BEFORE UPDATE ON public.secret_folder_versions FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_folders secret_folders_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_folders_updatedAt" BEFORE UPDATE ON public.secret_folders FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_imports secret_imports_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_imports_updatedAt" BEFORE UPDATE ON public.secret_imports FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_references secret_references_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_references_updatedAt" BEFORE UPDATE ON public.secret_references FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_rotations secret_rotations_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_rotations_updatedAt" BEFORE UPDATE ON public.secret_rotations FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_scanning_git_risks secret_scanning_git_risks_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_scanning_git_risks_updatedAt" BEFORE UPDATE ON public.secret_scanning_git_risks FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_sharing secret_sharing_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_sharing_updatedAt" BEFORE UPDATE ON public.secret_sharing FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_snapshots secret_snapshots_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_snapshots_updatedAt" BEFORE UPDATE ON public.secret_snapshots FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_tags secret_tags_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_tags_updatedAt" BEFORE UPDATE ON public.secret_tags FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_versions secret_versions_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_versions_updatedAt" BEFORE UPDATE ON public.secret_versions FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secret_versions_v2 secret_versions_v2_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secret_versions_v2_updatedAt" BEFORE UPDATE ON public.secret_versions_v2 FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secrets secrets_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secrets_updatedAt" BEFORE UPDATE ON public.secrets FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: secrets_v2 secrets_v2_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "secrets_v2_updatedAt" BEFORE UPDATE ON public.secrets_v2 FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: service_tokens service_tokens_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "service_tokens_updatedAt" BEFORE UPDATE ON public.service_tokens FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: slack_integrations slack_integrations_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "slack_integrations_updatedAt" BEFORE UPDATE ON public.slack_integrations FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: super_admin super_admin_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "super_admin_updatedAt" BEFORE UPDATE ON public.super_admin FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: trusted_ips trusted_ips_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "trusted_ips_updatedAt" BEFORE UPDATE ON public.trusted_ips FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: user_aliases user_aliases_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "user_aliases_updatedAt" BEFORE UPDATE ON public.user_aliases FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: user_group_membership user_group_membership_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "user_group_membership_updatedAt" BEFORE UPDATE ON public.user_group_membership FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: users users_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "users_updatedAt" BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: webhooks webhooks_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "webhooks_updatedAt" BEFORE UPDATE ON public.webhooks FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: workflow_integrations workflow_integrations_updatedAt; Type: TRIGGER; Schema: public; Owner: infisical
--

CREATE TRIGGER "workflow_integrations_updatedAt" BEFORE UPDATE ON public.workflow_integrations FOR EACH ROW EXECUTE FUNCTION public.on_update_timestamp();


--
-- Name: access_approval_policies_approvers access_approval_policies_approvers_approvergroupid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_policies_approvers
    ADD CONSTRAINT access_approval_policies_approvers_approvergroupid_foreign FOREIGN KEY ("approverGroupId") REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: access_approval_policies_approvers access_approval_policies_approvers_approveruserid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_policies_approvers
    ADD CONSTRAINT access_approval_policies_approvers_approveruserid_foreign FOREIGN KEY ("approverUserId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: access_approval_policies_approvers access_approval_policies_approvers_policyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_policies_approvers
    ADD CONSTRAINT access_approval_policies_approvers_policyid_foreign FOREIGN KEY ("policyId") REFERENCES public.access_approval_policies(id) ON DELETE CASCADE;


--
-- Name: access_approval_policies access_approval_policies_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_policies
    ADD CONSTRAINT access_approval_policies_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: access_approval_requests access_approval_requests_policyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests
    ADD CONSTRAINT access_approval_requests_policyid_foreign FOREIGN KEY ("policyId") REFERENCES public.access_approval_policies(id) ON DELETE CASCADE;


--
-- Name: access_approval_requests access_approval_requests_privilegeid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests
    ADD CONSTRAINT access_approval_requests_privilegeid_foreign FOREIGN KEY ("privilegeId") REFERENCES public.project_user_additional_privilege(id) ON DELETE CASCADE;


--
-- Name: access_approval_requests access_approval_requests_requestedby_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests
    ADD CONSTRAINT access_approval_requests_requestedby_foreign FOREIGN KEY ("requestedBy") REFERENCES public.project_memberships(id) ON DELETE CASCADE;


--
-- Name: access_approval_requests access_approval_requests_requestedbyuserid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests
    ADD CONSTRAINT access_approval_requests_requestedbyuserid_foreign FOREIGN KEY ("requestedByUserId") REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: access_approval_requests_reviewers access_approval_requests_reviewers_member_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests_reviewers
    ADD CONSTRAINT access_approval_requests_reviewers_member_foreign FOREIGN KEY (member) REFERENCES public.project_memberships(id) ON DELETE CASCADE;


--
-- Name: access_approval_requests_reviewers access_approval_requests_reviewers_requestid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests_reviewers
    ADD CONSTRAINT access_approval_requests_reviewers_requestid_foreign FOREIGN KEY ("requestId") REFERENCES public.access_approval_requests(id) ON DELETE CASCADE;


--
-- Name: access_approval_requests_reviewers access_approval_requests_reviewers_revieweruserid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.access_approval_requests_reviewers
    ADD CONSTRAINT access_approval_requests_reviewers_revieweruserid_foreign FOREIGN KEY ("reviewerUserId") REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: api_keys api_keys_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: audit_log_streams audit_log_streams_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.audit_log_streams
    ADD CONSTRAINT audit_log_streams_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: auth_token_sessions auth_token_sessions_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.auth_token_sessions
    ADD CONSTRAINT auth_token_sessions_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: auth_tokens auth_tokens_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: auth_tokens auth_tokens_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: backup_private_key backup_private_key_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.backup_private_key
    ADD CONSTRAINT backup_private_key_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: certificate_authorities certificate_authorities_activecacertid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_activecacertid_foreign FOREIGN KEY ("activeCaCertId") REFERENCES public.certificate_authority_certs(id);


--
-- Name: certificate_authorities certificate_authorities_parentcaid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_parentcaid_foreign FOREIGN KEY ("parentCaId") REFERENCES public.certificate_authorities(id) ON DELETE CASCADE;


--
-- Name: certificate_authorities certificate_authorities_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authorities
    ADD CONSTRAINT certificate_authorities_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: certificate_authority_certs certificate_authority_certs_caid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_certs
    ADD CONSTRAINT certificate_authority_certs_caid_foreign FOREIGN KEY ("caId") REFERENCES public.certificate_authorities(id) ON DELETE CASCADE;


--
-- Name: certificate_authority_certs certificate_authority_certs_casecretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_certs
    ADD CONSTRAINT certificate_authority_certs_casecretid_foreign FOREIGN KEY ("caSecretId") REFERENCES public.certificate_authority_secret(id) ON DELETE CASCADE;


--
-- Name: certificate_authority_crl certificate_authority_crl_caid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_crl
    ADD CONSTRAINT certificate_authority_crl_caid_foreign FOREIGN KEY ("caId") REFERENCES public.certificate_authorities(id) ON DELETE CASCADE;


--
-- Name: certificate_authority_crl certificate_authority_crl_casecretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_crl
    ADD CONSTRAINT certificate_authority_crl_casecretid_foreign FOREIGN KEY ("caSecretId") REFERENCES public.certificate_authority_secret(id) ON DELETE CASCADE;


--
-- Name: certificate_authority_secret certificate_authority_secret_caid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_authority_secret
    ADD CONSTRAINT certificate_authority_secret_caid_foreign FOREIGN KEY ("caId") REFERENCES public.certificate_authorities(id) ON DELETE CASCADE;


--
-- Name: certificate_bodies certificate_bodies_certid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_bodies
    ADD CONSTRAINT certificate_bodies_certid_foreign FOREIGN KEY ("certId") REFERENCES public.certificates(id) ON DELETE CASCADE;


--
-- Name: certificate_template_est_configs certificate_template_est_configs_certificatetemplateid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_template_est_configs
    ADD CONSTRAINT certificate_template_est_configs_certificatetemplateid_foreign FOREIGN KEY ("certificateTemplateId") REFERENCES public.certificate_templates(id) ON DELETE CASCADE;


--
-- Name: certificate_templates certificate_templates_caid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_templates
    ADD CONSTRAINT certificate_templates_caid_foreign FOREIGN KEY ("caId") REFERENCES public.certificate_authorities(id) ON DELETE CASCADE;


--
-- Name: certificate_templates certificate_templates_pkicollectionid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificate_templates
    ADD CONSTRAINT certificate_templates_pkicollectionid_foreign FOREIGN KEY ("pkiCollectionId") REFERENCES public.pki_collections(id) ON DELETE SET NULL;


--
-- Name: certificates certificates_cacertid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_cacertid_foreign FOREIGN KEY ("caCertId") REFERENCES public.certificate_authority_certs(id);


--
-- Name: certificates certificates_caid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_caid_foreign FOREIGN KEY ("caId") REFERENCES public.certificate_authorities(id) ON DELETE CASCADE;


--
-- Name: certificates certificates_certificatetemplateid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_certificatetemplateid_foreign FOREIGN KEY ("certificateTemplateId") REFERENCES public.certificate_templates(id) ON DELETE SET NULL;


--
-- Name: dynamic_secret_leases dynamic_secret_leases_dynamicsecretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.dynamic_secret_leases
    ADD CONSTRAINT dynamic_secret_leases_dynamicsecretid_foreign FOREIGN KEY ("dynamicSecretId") REFERENCES public.dynamic_secrets(id) ON DELETE CASCADE;


--
-- Name: dynamic_secrets dynamic_secrets_folderid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.dynamic_secrets
    ADD CONSTRAINT dynamic_secrets_folderid_foreign FOREIGN KEY ("folderId") REFERENCES public.secret_folders(id) ON DELETE CASCADE;


--
-- Name: external_group_org_role_mappings external_group_org_role_mappings_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.external_group_org_role_mappings
    ADD CONSTRAINT external_group_org_role_mappings_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: external_group_org_role_mappings external_group_org_role_mappings_roleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.external_group_org_role_mappings
    ADD CONSTRAINT external_group_org_role_mappings_roleid_foreign FOREIGN KEY ("roleId") REFERENCES public.org_roles(id);


--
-- Name: external_kms external_kms_kmskeyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.external_kms
    ADD CONSTRAINT external_kms_kmskeyid_foreign FOREIGN KEY ("kmsKeyId") REFERENCES public.kms_keys(id) ON DELETE CASCADE;


--
-- Name: git_app_install_sessions git_app_install_sessions_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_install_sessions
    ADD CONSTRAINT git_app_install_sessions_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: git_app_org git_app_org_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.git_app_org
    ADD CONSTRAINT git_app_org_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: group_project_membership_roles group_project_membership_roles_customroleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.group_project_membership_roles
    ADD CONSTRAINT group_project_membership_roles_customroleid_foreign FOREIGN KEY ("customRoleId") REFERENCES public.project_roles(id);


--
-- Name: group_project_membership_roles group_project_membership_roles_projectmembershipid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.group_project_membership_roles
    ADD CONSTRAINT group_project_membership_roles_projectmembershipid_foreign FOREIGN KEY ("projectMembershipId") REFERENCES public.group_project_memberships(id) ON DELETE CASCADE;


--
-- Name: group_project_memberships group_project_memberships_groupid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.group_project_memberships
    ADD CONSTRAINT group_project_memberships_groupid_foreign FOREIGN KEY ("groupId") REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: group_project_memberships group_project_memberships_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.group_project_memberships
    ADD CONSTRAINT group_project_memberships_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: groups groups_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: groups groups_roleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_roleid_foreign FOREIGN KEY ("roleId") REFERENCES public.org_roles(id);


--
-- Name: identity_access_tokens identity_access_tokens_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_access_tokens
    ADD CONSTRAINT identity_access_tokens_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_access_tokens identity_access_tokens_identityuaclientsecretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_access_tokens
    ADD CONSTRAINT identity_access_tokens_identityuaclientsecretid_foreign FOREIGN KEY ("identityUAClientSecretId") REFERENCES public.identity_ua_client_secrets(id) ON DELETE CASCADE;


--
-- Name: identity_aws_auths identity_aws_auths_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_aws_auths
    ADD CONSTRAINT identity_aws_auths_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_azure_auths identity_azure_auths_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_azure_auths
    ADD CONSTRAINT identity_azure_auths_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_gcp_auths identity_gcp_auths_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_gcp_auths
    ADD CONSTRAINT identity_gcp_auths_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_kubernetes_auths identity_kubernetes_auths_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_kubernetes_auths
    ADD CONSTRAINT identity_kubernetes_auths_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_metadata identity_metadata_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_metadata
    ADD CONSTRAINT identity_metadata_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_metadata identity_metadata_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_metadata
    ADD CONSTRAINT identity_metadata_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: identity_metadata identity_metadata_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_metadata
    ADD CONSTRAINT identity_metadata_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: identity_oidc_auths identity_oidc_auths_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_oidc_auths
    ADD CONSTRAINT identity_oidc_auths_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_org_memberships identity_org_memberships_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_org_memberships
    ADD CONSTRAINT identity_org_memberships_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_org_memberships identity_org_memberships_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_org_memberships
    ADD CONSTRAINT identity_org_memberships_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: identity_org_memberships identity_org_memberships_roleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_org_memberships
    ADD CONSTRAINT identity_org_memberships_roleid_foreign FOREIGN KEY ("roleId") REFERENCES public.org_roles(id);


--
-- Name: identity_project_additional_privilege identity_project_additional_privilege_projectmembershipid_forei; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_additional_privilege
    ADD CONSTRAINT identity_project_additional_privilege_projectmembershipid_forei FOREIGN KEY ("projectMembershipId") REFERENCES public.identity_project_memberships(id) ON DELETE CASCADE;


--
-- Name: identity_project_membership_role identity_project_membership_role_customroleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_membership_role
    ADD CONSTRAINT identity_project_membership_role_customroleid_foreign FOREIGN KEY ("customRoleId") REFERENCES public.project_roles(id);


--
-- Name: identity_project_membership_role identity_project_membership_role_projectmembershipid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_membership_role
    ADD CONSTRAINT identity_project_membership_role_projectmembershipid_foreign FOREIGN KEY ("projectMembershipId") REFERENCES public.identity_project_memberships(id) ON DELETE CASCADE;


--
-- Name: identity_project_memberships identity_project_memberships_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_memberships
    ADD CONSTRAINT identity_project_memberships_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_project_memberships identity_project_memberships_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_project_memberships
    ADD CONSTRAINT identity_project_memberships_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: identity_token_auths identity_token_auths_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_token_auths
    ADD CONSTRAINT identity_token_auths_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: identity_ua_client_secrets identity_ua_client_secrets_identityuaid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_ua_client_secrets
    ADD CONSTRAINT identity_ua_client_secrets_identityuaid_foreign FOREIGN KEY ("identityUAId") REFERENCES public.identity_universal_auths(id) ON DELETE CASCADE;


--
-- Name: identity_universal_auths identity_universal_auths_identityid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.identity_universal_auths
    ADD CONSTRAINT identity_universal_auths_identityid_foreign FOREIGN KEY ("identityId") REFERENCES public.identities(id) ON DELETE CASCADE;


--
-- Name: incident_contacts incident_contacts_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.incident_contacts
    ADD CONSTRAINT incident_contacts_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: integration_auths integration_auths_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.integration_auths
    ADD CONSTRAINT integration_auths_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: integrations integrations_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: integrations integrations_integrationauthid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_integrationauthid_foreign FOREIGN KEY ("integrationAuthId") REFERENCES public.integration_auths(id) ON DELETE CASCADE;


--
-- Name: internal_kms_key_version internal_kms_key_version_internalkmsid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.internal_kms_key_version
    ADD CONSTRAINT internal_kms_key_version_internalkmsid_foreign FOREIGN KEY ("internalKmsId") REFERENCES public.internal_kms(id) ON DELETE CASCADE;


--
-- Name: internal_kms internal_kms_kmskeyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.internal_kms
    ADD CONSTRAINT internal_kms_kmskeyid_foreign FOREIGN KEY ("kmsKeyId") REFERENCES public.kms_keys(id) ON DELETE CASCADE;


--
-- Name: kms_keys kms_keys_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.kms_keys
    ADD CONSTRAINT kms_keys_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: kms_keys kms_keys_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.kms_keys
    ADD CONSTRAINT kms_keys_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: ldap_configs ldap_configs_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.ldap_configs
    ADD CONSTRAINT ldap_configs_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: ldap_group_maps ldap_group_maps_groupid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.ldap_group_maps
    ADD CONSTRAINT ldap_group_maps_groupid_foreign FOREIGN KEY ("groupId") REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: ldap_group_maps ldap_group_maps_ldapconfigid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.ldap_group_maps
    ADD CONSTRAINT ldap_group_maps_ldapconfigid_foreign FOREIGN KEY ("ldapConfigId") REFERENCES public.ldap_configs(id) ON DELETE CASCADE;


--
-- Name: oidc_configs oidc_configs_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.oidc_configs
    ADD CONSTRAINT oidc_configs_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id);


--
-- Name: org_bots org_bots_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_bots
    ADD CONSTRAINT org_bots_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: org_memberships org_memberships_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: org_memberships org_memberships_roleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_roleid_foreign FOREIGN KEY ("roleId") REFERENCES public.org_roles(id);


--
-- Name: org_memberships org_memberships_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_memberships
    ADD CONSTRAINT org_memberships_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: org_roles org_roles_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.org_roles
    ADD CONSTRAINT org_roles_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: organizations organizations_kmsdefaultkeyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_kmsdefaultkeyid_foreign FOREIGN KEY ("kmsDefaultKeyId") REFERENCES public.kms_keys(id);


--
-- Name: pki_alerts pki_alerts_pkicollectionid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_alerts
    ADD CONSTRAINT pki_alerts_pkicollectionid_foreign FOREIGN KEY ("pkiCollectionId") REFERENCES public.pki_collections(id) ON DELETE CASCADE;


--
-- Name: pki_alerts pki_alerts_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_alerts
    ADD CONSTRAINT pki_alerts_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: pki_collection_items pki_collection_items_caid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_collection_items
    ADD CONSTRAINT pki_collection_items_caid_foreign FOREIGN KEY ("caId") REFERENCES public.certificate_authorities(id) ON DELETE CASCADE;


--
-- Name: pki_collection_items pki_collection_items_certid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_collection_items
    ADD CONSTRAINT pki_collection_items_certid_foreign FOREIGN KEY ("certId") REFERENCES public.certificates(id) ON DELETE CASCADE;


--
-- Name: pki_collection_items pki_collection_items_pkicollectionid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_collection_items
    ADD CONSTRAINT pki_collection_items_pkicollectionid_foreign FOREIGN KEY ("pkiCollectionId") REFERENCES public.pki_collections(id) ON DELETE CASCADE;


--
-- Name: pki_collections pki_collections_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.pki_collections
    ADD CONSTRAINT pki_collections_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_bots project_bots_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_bots
    ADD CONSTRAINT project_bots_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_bots project_bots_senderid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_bots
    ADD CONSTRAINT project_bots_senderid_foreign FOREIGN KEY ("senderId") REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: project_environments project_environments_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_environments
    ADD CONSTRAINT project_environments_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_keys project_keys_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_keys
    ADD CONSTRAINT project_keys_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_keys project_keys_receiverid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_keys
    ADD CONSTRAINT project_keys_receiverid_foreign FOREIGN KEY ("receiverId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: project_keys project_keys_senderid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_keys
    ADD CONSTRAINT project_keys_senderid_foreign FOREIGN KEY ("senderId") REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: project_memberships project_memberships_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_memberships
    ADD CONSTRAINT project_memberships_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_memberships project_memberships_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_memberships
    ADD CONSTRAINT project_memberships_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: project_roles project_roles_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_roles
    ADD CONSTRAINT project_roles_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_slack_configs project_slack_configs_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_slack_configs
    ADD CONSTRAINT project_slack_configs_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_slack_configs project_slack_configs_slackintegrationid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_slack_configs
    ADD CONSTRAINT project_slack_configs_slackintegrationid_foreign FOREIGN KEY ("slackIntegrationId") REFERENCES public.slack_integrations(id) ON DELETE CASCADE;


--
-- Name: project_user_additional_privilege project_user_additional_privilege_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_user_additional_privilege
    ADD CONSTRAINT project_user_additional_privilege_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_user_additional_privilege project_user_additional_privilege_projectmembershipid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_user_additional_privilege
    ADD CONSTRAINT project_user_additional_privilege_projectmembershipid_foreign FOREIGN KEY ("projectMembershipId") REFERENCES public.project_memberships(id) ON DELETE CASCADE;


--
-- Name: project_user_additional_privilege project_user_additional_privilege_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_user_additional_privilege
    ADD CONSTRAINT project_user_additional_privilege_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: project_user_membership_roles project_user_membership_roles_customroleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_user_membership_roles
    ADD CONSTRAINT project_user_membership_roles_customroleid_foreign FOREIGN KEY ("customRoleId") REFERENCES public.project_roles(id);


--
-- Name: project_user_membership_roles project_user_membership_roles_projectmembershipid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.project_user_membership_roles
    ADD CONSTRAINT project_user_membership_roles_projectmembershipid_foreign FOREIGN KEY ("projectMembershipId") REFERENCES public.project_memberships(id) ON DELETE CASCADE;


--
-- Name: projects projects_kmscertificatekeyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_kmscertificatekeyid_foreign FOREIGN KEY ("kmsCertificateKeyId") REFERENCES public.kms_keys(id);


--
-- Name: projects projects_kmssecretmanagerkeyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_kmssecretmanagerkeyid_foreign FOREIGN KEY ("kmsSecretManagerKeyId") REFERENCES public.kms_keys(id);


--
-- Name: projects projects_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: saml_configs saml_configs_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.saml_configs
    ADD CONSTRAINT saml_configs_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: scim_tokens scim_tokens_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: secret_approval_policies_approvers secret_approval_policies_approvers_approvergroupid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_policies_approvers
    ADD CONSTRAINT secret_approval_policies_approvers_approvergroupid_foreign FOREIGN KEY ("approverGroupId") REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: secret_approval_policies_approvers secret_approval_policies_approvers_approveruserid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_policies_approvers
    ADD CONSTRAINT secret_approval_policies_approvers_approveruserid_foreign FOREIGN KEY ("approverUserId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: secret_approval_policies_approvers secret_approval_policies_approvers_policyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_policies_approvers
    ADD CONSTRAINT secret_approval_policies_approvers_policyid_foreign FOREIGN KEY ("policyId") REFERENCES public.secret_approval_policies(id) ON DELETE CASCADE;


--
-- Name: secret_approval_policies secret_approval_policies_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_policies
    ADD CONSTRAINT secret_approval_policies_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_approval_request_secret_tags secret_approval_request_secret_tags_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_request_secret_tags
    ADD CONSTRAINT secret_approval_request_secret_tags_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secret_approval_requests_secrets(id) ON DELETE CASCADE;


--
-- Name: secret_approval_request_secret_tags secret_approval_request_secret_tags_tagid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_request_secret_tags
    ADD CONSTRAINT secret_approval_request_secret_tags_tagid_foreign FOREIGN KEY ("tagId") REFERENCES public.secret_tags(id) ON DELETE CASCADE;


--
-- Name: secret_approval_request_secret_tags_v2 secret_approval_request_secret_tags_v2_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_request_secret_tags_v2
    ADD CONSTRAINT secret_approval_request_secret_tags_v2_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secret_approval_requests_secrets_v2(id) ON DELETE CASCADE;


--
-- Name: secret_approval_request_secret_tags_v2 secret_approval_request_secret_tags_v2_tagid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_request_secret_tags_v2
    ADD CONSTRAINT secret_approval_request_secret_tags_v2_tagid_foreign FOREIGN KEY ("tagId") REFERENCES public.secret_tags(id) ON DELETE CASCADE;


--
-- Name: secret_approval_requests secret_approval_requests_committeruserid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests
    ADD CONSTRAINT secret_approval_requests_committeruserid_foreign FOREIGN KEY ("committerUserId") REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: secret_approval_requests secret_approval_requests_folderid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests
    ADD CONSTRAINT secret_approval_requests_folderid_foreign FOREIGN KEY ("folderId") REFERENCES public.secret_folders(id) ON DELETE CASCADE;


--
-- Name: secret_approval_requests secret_approval_requests_policyid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests
    ADD CONSTRAINT secret_approval_requests_policyid_foreign FOREIGN KEY ("policyId") REFERENCES public.secret_approval_policies(id) ON DELETE CASCADE;


--
-- Name: secret_approval_requests_reviewers secret_approval_requests_reviewers_requestid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_reviewers
    ADD CONSTRAINT secret_approval_requests_reviewers_requestid_foreign FOREIGN KEY ("requestId") REFERENCES public.secret_approval_requests(id) ON DELETE CASCADE;


--
-- Name: secret_approval_requests_reviewers secret_approval_requests_reviewers_revieweruserid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_reviewers
    ADD CONSTRAINT secret_approval_requests_reviewers_revieweruserid_foreign FOREIGN KEY ("reviewerUserId") REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: secret_approval_requests_secrets secret_approval_requests_secrets_requestid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets
    ADD CONSTRAINT secret_approval_requests_secrets_requestid_foreign FOREIGN KEY ("requestId") REFERENCES public.secret_approval_requests(id) ON DELETE CASCADE;


--
-- Name: secret_approval_requests_secrets secret_approval_requests_secrets_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets
    ADD CONSTRAINT secret_approval_requests_secrets_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secrets(id) ON DELETE SET NULL;


--
-- Name: secret_approval_requests_secrets secret_approval_requests_secrets_secretversion_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets
    ADD CONSTRAINT secret_approval_requests_secrets_secretversion_foreign FOREIGN KEY ("secretVersion") REFERENCES public.secret_versions(id) ON DELETE SET NULL;


--
-- Name: secret_approval_requests_secrets_v2 secret_approval_requests_secrets_v2_requestid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets_v2
    ADD CONSTRAINT secret_approval_requests_secrets_v2_requestid_foreign FOREIGN KEY ("requestId") REFERENCES public.secret_approval_requests(id) ON DELETE CASCADE;


--
-- Name: secret_approval_requests_secrets_v2 secret_approval_requests_secrets_v2_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets_v2
    ADD CONSTRAINT secret_approval_requests_secrets_v2_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secrets_v2(id) ON DELETE SET NULL;


--
-- Name: secret_approval_requests_secrets_v2 secret_approval_requests_secrets_v2_secretversion_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests_secrets_v2
    ADD CONSTRAINT secret_approval_requests_secrets_v2_secretversion_foreign FOREIGN KEY ("secretVersion") REFERENCES public.secret_versions_v2(id) ON DELETE SET NULL;


--
-- Name: secret_approval_requests secret_approval_requests_statuschangedbyuserid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_approval_requests
    ADD CONSTRAINT secret_approval_requests_statuschangedbyuserid_foreign FOREIGN KEY ("statusChangedByUserId") REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: secret_blind_indexes secret_blind_indexes_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_blind_indexes
    ADD CONSTRAINT secret_blind_indexes_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: secret_folder_versions secret_folder_versions_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_folder_versions
    ADD CONSTRAINT secret_folder_versions_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_folders secret_folders_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_folders
    ADD CONSTRAINT secret_folders_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_folders secret_folders_parentid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_folders
    ADD CONSTRAINT secret_folders_parentid_foreign FOREIGN KEY ("parentId") REFERENCES public.secret_folders(id) ON DELETE CASCADE;


--
-- Name: secret_imports secret_imports_folderid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_imports
    ADD CONSTRAINT secret_imports_folderid_foreign FOREIGN KEY ("folderId") REFERENCES public.secret_folders(id) ON DELETE CASCADE;


--
-- Name: secret_imports secret_imports_importenv_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_imports
    ADD CONSTRAINT secret_imports_importenv_foreign FOREIGN KEY ("importEnv") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_references secret_references_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_references
    ADD CONSTRAINT secret_references_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secrets(id) ON DELETE CASCADE;


--
-- Name: secret_references_v2 secret_references_v2_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_references_v2
    ADD CONSTRAINT secret_references_v2_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secrets_v2(id) ON DELETE CASCADE;


--
-- Name: secret_rotation_output_v2 secret_rotation_output_v2_rotationid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotation_output_v2
    ADD CONSTRAINT secret_rotation_output_v2_rotationid_foreign FOREIGN KEY ("rotationId") REFERENCES public.secret_rotations(id) ON DELETE CASCADE;


--
-- Name: secret_rotation_output_v2 secret_rotation_output_v2_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotation_output_v2
    ADD CONSTRAINT secret_rotation_output_v2_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secrets_v2(id) ON DELETE CASCADE;


--
-- Name: secret_rotation_outputs secret_rotation_outputs_rotationid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotation_outputs
    ADD CONSTRAINT secret_rotation_outputs_rotationid_foreign FOREIGN KEY ("rotationId") REFERENCES public.secret_rotations(id) ON DELETE CASCADE;


--
-- Name: secret_rotation_outputs secret_rotation_outputs_secretid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotation_outputs
    ADD CONSTRAINT secret_rotation_outputs_secretid_foreign FOREIGN KEY ("secretId") REFERENCES public.secrets(id) ON DELETE CASCADE;


--
-- Name: secret_rotations secret_rotations_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_rotations
    ADD CONSTRAINT secret_rotations_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_scanning_git_risks secret_scanning_git_risks_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_scanning_git_risks
    ADD CONSTRAINT secret_scanning_git_risks_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: secret_sharing secret_sharing_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_sharing
    ADD CONSTRAINT secret_sharing_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: secret_sharing secret_sharing_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_sharing
    ADD CONSTRAINT secret_sharing_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_folders secret_snapshot_folders_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_folders
    ADD CONSTRAINT secret_snapshot_folders_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_folders secret_snapshot_folders_folderversionid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_folders
    ADD CONSTRAINT secret_snapshot_folders_folderversionid_foreign FOREIGN KEY ("folderVersionId") REFERENCES public.secret_folder_versions(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_folders secret_snapshot_folders_snapshotid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_folders
    ADD CONSTRAINT secret_snapshot_folders_snapshotid_foreign FOREIGN KEY ("snapshotId") REFERENCES public.secret_snapshots(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_secrets secret_snapshot_secrets_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets
    ADD CONSTRAINT secret_snapshot_secrets_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_secrets secret_snapshot_secrets_secretversionid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets
    ADD CONSTRAINT secret_snapshot_secrets_secretversionid_foreign FOREIGN KEY ("secretVersionId") REFERENCES public.secret_versions(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_secrets secret_snapshot_secrets_snapshotid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets
    ADD CONSTRAINT secret_snapshot_secrets_snapshotid_foreign FOREIGN KEY ("snapshotId") REFERENCES public.secret_snapshots(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_secrets_v2 secret_snapshot_secrets_v2_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets_v2
    ADD CONSTRAINT secret_snapshot_secrets_v2_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_secrets_v2 secret_snapshot_secrets_v2_secretversionid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets_v2
    ADD CONSTRAINT secret_snapshot_secrets_v2_secretversionid_foreign FOREIGN KEY ("secretVersionId") REFERENCES public.secret_versions_v2(id) ON DELETE CASCADE;


--
-- Name: secret_snapshot_secrets_v2 secret_snapshot_secrets_v2_snapshotid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshot_secrets_v2
    ADD CONSTRAINT secret_snapshot_secrets_v2_snapshotid_foreign FOREIGN KEY ("snapshotId") REFERENCES public.secret_snapshots(id) ON DELETE CASCADE;


--
-- Name: secret_snapshots secret_snapshots_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_snapshots
    ADD CONSTRAINT secret_snapshots_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_tag_junction secret_tag_junction_secret_tagsid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_tag_junction
    ADD CONSTRAINT secret_tag_junction_secret_tagsid_foreign FOREIGN KEY ("secret_tagsId") REFERENCES public.secret_tags(id) ON DELETE CASCADE;


--
-- Name: secret_tag_junction secret_tag_junction_secretsid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_tag_junction
    ADD CONSTRAINT secret_tag_junction_secretsid_foreign FOREIGN KEY ("secretsId") REFERENCES public.secrets(id) ON DELETE CASCADE;


--
-- Name: secret_tags secret_tags_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_tags
    ADD CONSTRAINT secret_tags_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: secret_v2_tag_junction secret_v2_tag_junction_secret_tagsid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_v2_tag_junction
    ADD CONSTRAINT secret_v2_tag_junction_secret_tagsid_foreign FOREIGN KEY ("secret_tagsId") REFERENCES public.secret_tags(id) ON DELETE CASCADE;


--
-- Name: secret_v2_tag_junction secret_v2_tag_junction_secrets_v2id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_v2_tag_junction
    ADD CONSTRAINT secret_v2_tag_junction_secrets_v2id_foreign FOREIGN KEY ("secrets_v2Id") REFERENCES public.secrets_v2(id) ON DELETE CASCADE;


--
-- Name: secret_version_tag_junction secret_version_tag_junction_secret_tagsid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_version_tag_junction
    ADD CONSTRAINT secret_version_tag_junction_secret_tagsid_foreign FOREIGN KEY ("secret_tagsId") REFERENCES public.secret_tags(id) ON DELETE CASCADE;


--
-- Name: secret_version_tag_junction secret_version_tag_junction_secret_versionsid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_version_tag_junction
    ADD CONSTRAINT secret_version_tag_junction_secret_versionsid_foreign FOREIGN KEY ("secret_versionsId") REFERENCES public.secret_versions(id) ON DELETE CASCADE;


--
-- Name: secret_version_v2_tag_junction secret_version_v2_tag_junction_secret_tagsid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_version_v2_tag_junction
    ADD CONSTRAINT secret_version_v2_tag_junction_secret_tagsid_foreign FOREIGN KEY ("secret_tagsId") REFERENCES public.secret_tags(id) ON DELETE CASCADE;


--
-- Name: secret_version_v2_tag_junction secret_version_v2_tag_junction_secret_versions_v2id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_version_v2_tag_junction
    ADD CONSTRAINT secret_version_v2_tag_junction_secret_versions_v2id_foreign FOREIGN KEY ("secret_versions_v2Id") REFERENCES public.secret_versions_v2(id) ON DELETE CASCADE;


--
-- Name: secret_versions secret_versions_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_versions secret_versions_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: secret_versions_v2 secret_versions_v2_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_versions_v2
    ADD CONSTRAINT secret_versions_v2_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: secret_versions_v2 secret_versions_v2_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secret_versions_v2
    ADD CONSTRAINT secret_versions_v2_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: secrets secrets_folderid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_folderid_foreign FOREIGN KEY ("folderId") REFERENCES public.secret_folders(id) ON DELETE CASCADE;


--
-- Name: secrets secrets_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: secrets_v2 secrets_v2_folderid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secrets_v2
    ADD CONSTRAINT secrets_v2_folderid_foreign FOREIGN KEY ("folderId") REFERENCES public.secret_folders(id) ON DELETE CASCADE;


--
-- Name: secrets_v2 secrets_v2_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.secrets_v2
    ADD CONSTRAINT secrets_v2_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: service_tokens service_tokens_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.service_tokens
    ADD CONSTRAINT service_tokens_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: slack_integrations slack_integrations_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.slack_integrations
    ADD CONSTRAINT slack_integrations_id_foreign FOREIGN KEY (id) REFERENCES public.workflow_integrations(id) ON DELETE CASCADE;


--
-- Name: super_admin super_admin_defaultauthorgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.super_admin
    ADD CONSTRAINT super_admin_defaultauthorgid_foreign FOREIGN KEY ("defaultAuthOrgId") REFERENCES public.organizations(id) ON DELETE SET NULL;


--
-- Name: trusted_ips trusted_ips_projectid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.trusted_ips
    ADD CONSTRAINT trusted_ips_projectid_foreign FOREIGN KEY ("projectId") REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: user_actions user_actions_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_actions
    ADD CONSTRAINT user_actions_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_aliases user_aliases_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_aliases
    ADD CONSTRAINT user_aliases_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: user_aliases user_aliases_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_aliases
    ADD CONSTRAINT user_aliases_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_encryption_keys user_encryption_keys_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_encryption_keys
    ADD CONSTRAINT user_encryption_keys_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_group_membership user_group_membership_groupid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT user_group_membership_groupid_foreign FOREIGN KEY ("groupId") REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: user_group_membership user_group_membership_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT user_group_membership_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: webhooks webhooks_envid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_envid_foreign FOREIGN KEY ("envId") REFERENCES public.project_environments(id) ON DELETE CASCADE;


--
-- Name: workflow_integrations workflow_integrations_orgid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: infisical
--

ALTER TABLE ONLY public.workflow_integrations
    ADD CONSTRAINT workflow_integrations_orgid_foreign FOREIGN KEY ("orgId") REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

