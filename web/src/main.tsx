import { createRoot } from "react-dom/client"
import { RouterProvider } from "@tanstack/react-router"
import { QueryClientProvider } from "@tanstack/react-query"
import { createAppRouter } from "./app/router"
import { createQueryClient } from "./app/query"
import { AppearanceProvider } from "./app/appearance"
import "./styles.css"

const router = createAppRouter()
const queryClient = createQueryClient()

const root = document.getElementById("root")
if (!root) throw new Error("Application root is missing")
createRoot(root).render(
  <QueryClientProvider client={queryClient}>
    <AppearanceProvider>
      <RouterProvider router={router} />
    </AppearanceProvider>
  </QueryClientProvider>,
)
