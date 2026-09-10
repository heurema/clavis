import { createFileRoute } from "@tanstack/react-router"
import { StatusPage } from "../components/StatusPage"

export const Route = createFileRoute("/")({ component: StatusPage })
