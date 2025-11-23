import { useState, useEffect, createContext, useContext } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Link, useNavigate, Navigate } from "react-router-dom";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Brain, Upload, MessageSquare, History, FileText, UserCircle, Stethoscope, LogOut, Calendar, User } from "lucide-react";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchUser();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchUser = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setUser(response.data);
    } catch (error) {
      console.error('Auth error:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = (token, userData) => {
    localStorage.setItem('token', token);
    setToken(token);
    setUser(userData);
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  const updateUser = (userData) => {
    setUser(userData);
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading, updateUser }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => useContext(AuthContext);

const Navigation = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-white/80 backdrop-blur-md border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
        <Link to="/" className="flex items-center gap-2 text-2xl font-bold" data-testid="logo-link">
          <Brain className="w-8 h-8 text-blue-600" />
          <span className="bg-gradient-to-r from-blue-600 to-cyan-500 bg-clip-text text-transparent">NeuroScan AI</span>
        </Link>
        <div className="flex gap-6 items-center">
          <Button variant="ghost" onClick={() => navigate('/')} data-testid="nav-home-btn">Home</Button>
          {user ? (
            <>
              <Button variant="ghost" onClick={() => navigate('/dashboard')} data-testid="nav-dashboard-btn">Dashboard</Button>
              <div className="flex items-center gap-3">
                <span className="text-sm text-gray-700" data-testid="user-name">{user.full_name}</span>
                <Button variant="outline" size="sm" onClick={logout} data-testid="logout-btn">
                  <LogOut className="w-4 h-4 mr-2" />
                  Logout
                </Button>
              </div>
            </>
          ) : (
            <>
              <Button variant="ghost" onClick={() => navigate('/login')} data-testid="nav-login-btn">Login</Button>
              <Button className="bg-blue-600 hover:bg-blue-700" onClick={() => navigate('/signup')} data-testid="nav-signup-btn">Sign Up</Button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

const HomePage = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  
  return (
    <div className="min-h-screen">
      <Navigation />
      <div className="pt-20">
        {/* Hero Section */}
        <section className="relative px-6 py-20 bg-gradient-to-br from-blue-50 via-cyan-50 to-white overflow-hidden">
          <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
          <div className="max-w-6xl mx-auto text-center relative z-10">
            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold mb-6 bg-gradient-to-r from-blue-700 via-cyan-600 to-blue-500 bg-clip-text text-transparent" data-testid="hero-title">
              Advanced Brain Tumor Detection
            </h1>
            <p className="text-lg sm:text-xl text-gray-700 mb-10 max-w-3xl mx-auto" data-testid="hero-subtitle">
              Harness the power of artificial intelligence to analyze MRI scans with precision. Get instant insights, expert recommendations, and comprehensive reports.
            </p>
            <Button 
              size="lg" 
              className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-8 py-6 text-lg rounded-full shadow-xl transform hover:scale-105 transition-all"
              onClick={() => navigate(user ? '/dashboard' : '/login')}
              data-testid="hero-cta-btn"
            >
              {user ? 'Go to Dashboard' : 'Get Started'}
            </Button>
          </div>
        </section>

        {/* Features Section */}
        <section className="px-6 py-16 bg-white" data-testid="features-section">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-3xl sm:text-4xl font-bold text-center mb-12 text-gray-800">How NeuroScan AI Works</h2>
            <div className="grid md:grid-cols-3 gap-8">
              <Card className="border-2 hover:border-blue-400 transition-all hover:shadow-lg" data-testid="feature-upload-card">
                <CardHeader>
                  <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-2xl flex items-center justify-center mb-4">
                    <Upload className="w-8 h-8 text-white" />
                  </div>
                  <CardTitle className="text-xl">Upload MRI Scan</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-base">
                    Securely upload your brain MRI images in standard formats. Our platform ensures data privacy and encryption.
                  </CardDescription>
                </CardContent>
              </Card>

              <Card className="border-2 hover:border-cyan-400 transition-all hover:shadow-lg" data-testid="feature-analysis-card">
                <CardHeader>
                  <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-teal-500 rounded-2xl flex items-center justify-center mb-4">
                    <Brain className="w-8 h-8 text-white" />
                  </div>
                  <CardTitle className="text-xl">AI-Powered Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-base">
                    Advanced algorithms analyze your scan in seconds, detecting anomalies with high accuracy using state-of-the-art AI models.
                  </CardDescription>
                </CardContent>
              </Card>

              <Card className="border-2 hover:border-teal-400 transition-all hover:shadow-lg" data-testid="feature-report-card">
                <CardHeader>
                  <div className="w-16 h-16 bg-gradient-to-br from-teal-500 to-green-500 rounded-2xl flex items-center justify-center mb-4">
                    <FileText className="w-8 h-8 text-white" />
                  </div>
                  <CardTitle className="text-xl">Detailed Reports</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-base">
                    Receive comprehensive reports with findings, severity assessment, and recommended specialists for consultation.
                  </CardDescription>
                </CardContent>
              </Card>
            </div>
          </div>
        </section>

        {/* About Section */}
        <section className="px-6 py-16 bg-gradient-to-br from-gray-50 to-blue-50" data-testid="about-section">
          <div className="max-w-4xl mx-auto text-center">
            <h2 className="text-3xl sm:text-4xl font-bold mb-6 text-gray-800">About Brain Tumors</h2>
            <p className="text-lg text-gray-700 leading-relaxed">
              Brain tumors are abnormal growths of cells in the brain. Early detection through MRI imaging is crucial for effective treatment. 
              Our AI-powered platform assists healthcare professionals in identifying potential abnormalities quickly and accurately, 
              enabling timely intervention and better patient outcomes.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
};

const LoginPage = () => {
  const navigate = useNavigate();
  const { login, user } = useAuth();
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [isLoading, setIsLoading] = useState(false);

  if (user) {
    return <Navigate to="/dashboard" />;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await axios.post(`${API}/auth/login`, formData);
      login(response.data.access_token, response.data.user);
      toast.success('Welcome back!');
      navigate('/dashboard');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-cyan-50 to-white">
      <Navigation />
      <div className="pt-24 px-6 pb-12 flex items-center justify-center">
        <Card className="w-full max-w-md" data-testid="login-card">
          <CardHeader className="text-center">
            <div className="w-20 h-20 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-full flex items-center justify-center mx-auto mb-4">
              <Brain className="w-10 h-10 text-white" />
            </div>
            <CardTitle className="text-3xl font-bold">Welcome Back</CardTitle>
            <CardDescription>Sign in to access your medical dashboard</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="your@email.com"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                  data-testid="login-email-input"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required
                  data-testid="login-password-input"
                />
              </div>
              <Button 
                type="submit" 
                className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
                disabled={isLoading}
                data-testid="login-submit-btn"
              >
                {isLoading ? 'Signing in...' : 'Sign In'}
              </Button>
            </form>
            <div className="mt-4 text-center">
              <p className="text-sm text-gray-600">
                Don't have an account?{' '}
                <button
                  onClick={() => navigate('/signup')}
                  className="text-blue-600 hover:underline font-medium"
                  data-testid="goto-signup-btn"
                >
                  Sign up
                </button>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

const SignupPage = () => {
  const navigate = useNavigate();
  const { login, user } = useAuth();
  const [formData, setFormData] = useState({ email: '', password: '', full_name: '' });
  const [isLoading, setIsLoading] = useState(false);

  if (user) {
    return <Navigate to="/dashboard" />;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await axios.post(`${API}/auth/register`, formData);
      login(response.data.access_token, response.data.user);
      toast.success('Account created successfully!');
      navigate('/dashboard');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-cyan-50 to-white">
      <Navigation />
      <div className="pt-24 px-6 pb-12 flex items-center justify-center">
        <Card className="w-full max-w-md" data-testid="signup-card">
          <CardHeader className="text-center">
            <div className="w-20 h-20 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-full flex items-center justify-center mx-auto mb-4">
              <Brain className="w-10 h-10 text-white" />
            </div>
            <CardTitle className="text-3xl font-bold">Create Account</CardTitle>
            <CardDescription>Join NeuroScan AI for advanced brain health monitoring</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="full_name">Full Name</Label>
                <Input
                  id="full_name"
                  type="text"
                  placeholder="John Doe"
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  required
                  data-testid="signup-name-input"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="your@email.com"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                  data-testid="signup-email-input"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required
                  minLength={6}
                  data-testid="signup-password-input"
                />
              </div>
              <Button 
                type="submit" 
                className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
                disabled={isLoading}
                data-testid="signup-submit-btn"
              >
                {isLoading ? 'Creating account...' : 'Sign Up'}
              </Button>
            </form>
            <div className="mt-4 text-center">
              <p className="text-sm text-gray-600">
                Already have an account?{' '}
                <button
                  onClick={() => navigate('/login')}
                  className="text-blue-600 hover:underline font-medium"
                  data-testid="goto-login-btn"
                >
                  Sign in
                </button>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

const BookAppointmentDialog = ({ doctor, onSuccess }) => {
  const [open, setOpen] = useState(false);
  const [formData, setFormData] = useState({
    appointment_date: '',
    appointment_time: '',
    reason: ''
  });
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      await axios.post(`${API}/appointments`, {
        doctor_id: doctor.id,
        ...formData
      });
      toast.success('Appointment booked successfully!');
      setOpen(false);
      setFormData({ appointment_date: '', appointment_time: '', reason: '' });
      if (onSuccess) onSuccess();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to book appointment');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700" data-testid="book-appointment-btn">
          <Calendar className="w-4 h-4 mr-2" />
          Book Appointment
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md" data-testid="appointment-dialog">
        <DialogHeader>
          <DialogTitle>Book Appointment</DialogTitle>
          <DialogDescription>
            Schedule an appointment with {doctor.name}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="date">Appointment Date</Label>
            <Input
              id="date"
              type="date"
              value={formData.appointment_date}
              onChange={(e) => setFormData({ ...formData, appointment_date: e.target.value })}
              required
              data-testid="appointment-date-input"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="time">Appointment Time</Label>
            <Input
              id="time"
              type="time"
              value={formData.appointment_time}
              onChange={(e) => setFormData({ ...formData, appointment_time: e.target.value })}
              required
              data-testid="appointment-time-input"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="reason">Reason for Visit</Label>
            <Textarea
              id="reason"
              placeholder="Describe your symptoms or reason for consultation..."
              value={formData.reason}
              onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
              required
              rows={3}
              data-testid="appointment-reason-input"
            />
          </div>
          <Button 
            type="submit" 
            className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
            disabled={isLoading}
            data-testid="confirm-appointment-btn"
          >
            {isLoading ? 'Booking...' : 'Confirm Booking'}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
};

const Dashboard = () => {
  const { user, updateUser } = useAuth();
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [doctors, setDoctors] = useState([]);
  const [appointments, setAppointments] = useState([]);
  const [profileData, setProfileData] = useState({});
  const [isUpdatingProfile, setIsUpdatingProfile] = useState(false);
  const sessionId = "session_" + Date.now();

  useEffect(() => {
    if (user) {
      loadScanHistory();
      loadDoctors();
      loadAppointments();
      setProfileData({
        full_name: user.full_name || '',
        phone: user.phone || '',
        age: user.age || '',
        gender: user.gender || '',
        address: user.address || '',
        medical_history: user.medical_history || ''
      });
    }
  }, [user]);

  const loadScanHistory = async () => {
    try {
      const response = await axios.get(`${API}/scans/${user.id}`);
      setScanHistory(response.data);
    } catch (error) {
      console.error("Error loading history:", error);
    }
  };

  const loadDoctors = async () => {
    try {
      const response = await axios.get(`${API}/doctors`);
      setDoctors(response.data);
      
      // Initialize doctors if empty
      if (response.data.length === 0) {
        const defaultDoctors = [
          { name: "Dr. Sarah Mitchell", specialization: "Neurosurgeon", experience: "15 years", location: "New York Medical Center", contact: "+1-555-0101", rating: 4.9 },
          { name: "Dr. James Carter", specialization: "Neuro-oncologist", experience: "12 years", location: "Boston Brain Institute", contact: "+1-555-0102", rating: 4.8 },
          { name: "Dr. Emily Zhang", specialization: "Neurologist", experience: "10 years", location: "San Francisco Neurology Clinic", contact: "+1-555-0103", rating: 4.7 },
        ];
        
        for (const doc of defaultDoctors) {
          await axios.post(`${API}/doctors`, doc);
        }
        setDoctors(defaultDoctors);
      }
    } catch (error) {
      console.error("Error loading doctors:", error);
    }
  };

  const loadAppointments = async () => {
    try {
      const response = await axios.get(`${API}/appointments`);
      setAppointments(response.data);
    } catch (error) {
      console.error("Error loading appointments:", error);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setPreviewUrl(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      toast.error("Please select an MRI image first");
      return;
    }

    setIsAnalyzing(true);
    try {
      const reader = new FileReader();
      reader.onloadend = async () => {
        const base64Image = reader.result.split(',')[1];
        
        const response = await axios.post(`${API}/scan`, {
          user_id: user.id,
          image_data: base64Image
        });
        
        setScanResult(response.data);
        toast.success("Scan analysis complete!");
        loadScanHistory();
      };
      reader.readAsDataURL(selectedFile);
    } catch (error) {
      console.error("Scan error:", error);
      toast.error(error.response?.data?.detail || "Analysis failed. Please try again.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleChat = async () => {
    if (!chatInput.trim()) return;

    const userMessage = chatInput;
    setChatMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setChatInput("");
    setIsChatLoading(true);

    try {
      const response = await axios.post(`${API}/chat`, {
        user_id: user.id,
        session_id: sessionId,
        message: userMessage
      });
      
      setChatMessages(prev => [...prev, { role: 'assistant', content: response.data.response }]);
    } catch (error) {
      console.error("Chat error:", error);
      toast.error("Failed to get response");
    } finally {
      setIsChatLoading(false);
    }
  };

  const downloadReport = async (scanId) => {
    try {
      const response = await axios.get(`${API}/report/${scanId}`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `neuroscan_report_${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      toast.success("Report downloaded!");
    } catch (error) {
      console.error("Download error:", error);
      toast.error("Failed to download report");
    }
  };

  const handleCancelAppointment = async (appointmentId) => {
    try {
      await axios.delete(`${API}/appointments/${appointmentId}`);
      toast.success("Appointment cancelled");
      loadAppointments();
    } catch (error) {
      toast.error("Failed to cancel appointment");
    }
  };

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setIsUpdatingProfile(true);

    try {
      const response = await axios.put(`${API}/profile`, profileData);
      updateUser(response.data);
      toast.success("Profile updated successfully!");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to update profile");
    } finally {
      setIsUpdatingProfile(false);
    }
  };

  if (!user) {
    return <Navigate to="/login" />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-cyan-50">
      <Navigation />
      <div className="pt-24 px-6 pb-12">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <h1 className="text-4xl font-bold text-gray-800" data-testid="dashboard-title">Medical Dashboard</h1>
            <p className="text-gray-600 mt-2">Welcome back, {user.full_name}</p>
          </div>
          
          <Tabs defaultValue="scan" className="w-full">
            <TabsList className="grid w-full grid-cols-6 mb-8" data-testid="dashboard-tabs">
              <TabsTrigger value="scan" data-testid="tab-scan"><Upload className="w-4 h-4 mr-2" />Scan</TabsTrigger>
              <TabsTrigger value="history" data-testid="tab-history"><History className="w-4 h-4 mr-2" />History</TabsTrigger>
              <TabsTrigger value="chat" data-testid="tab-chat"><MessageSquare className="w-4 h-4 mr-2" />Assistant</TabsTrigger>
              <TabsTrigger value="doctors" data-testid="tab-doctors"><Stethoscope className="w-4 h-4 mr-2" />Doctors</TabsTrigger>
              <TabsTrigger value="appointments" data-testid="tab-appointments"><Calendar className="w-4 h-4 mr-2" />Appointments</TabsTrigger>
              <TabsTrigger value="profile" data-testid="tab-profile"><User className="w-4 h-4 mr-2" />Profile</TabsTrigger>
            </TabsList>

            <TabsContent value="scan">
              <div className="grid lg:grid-cols-2 gap-6">
                <Card data-testid="upload-card">
                  <CardHeader>
                    <CardTitle>Upload MRI Scan</CardTitle>
                    <CardDescription>Select a brain MRI image for AI analysis</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-400 transition-colors">
                        <input
                          type="file"
                          accept="image/*"
                          onChange={handleFileSelect}
                          className="hidden"
                          id="file-upload"
                          data-testid="file-input"
                        />
                        <label htmlFor="file-upload" className="cursor-pointer" data-testid="file-upload-label">
                          <Upload className="w-12 h-12 mx-auto mb-4 text-gray-400" />
                          <p className="text-lg font-medium text-gray-700">Click to upload MRI image</p>
                          <p className="text-sm text-gray-500 mt-2">PNG, JPG, JPEG up to 10MB</p>
                        </label>
                      </div>
                      {previewUrl && (
                        <div className="mt-4" data-testid="preview-container">
                          <img src={previewUrl} alt="MRI Preview" className="w-full h-64 object-cover rounded-lg" data-testid="preview-image" />
                        </div>
                      )}
                      <Button 
                        onClick={handleScan} 
                        disabled={!selectedFile || isAnalyzing}
                        className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
                        data-testid="analyze-btn"
                      >
                        {isAnalyzing ? "Analyzing..." : "Analyze Scan"}
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {scanResult && (
                  <Card className="border-2 border-blue-200 bg-gradient-to-br from-blue-50 to-cyan-50" data-testid="results-card">
                    <CardHeader>
                      <CardTitle className="text-2xl">Analysis Results</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="p-4 bg-white rounded-lg">
                        <p className="text-sm font-medium text-gray-600">Tumor Detection</p>
                        <p className={`text-2xl font-bold ${scanResult.tumor_detected ? 'text-red-600' : 'text-green-600'}`} data-testid="tumor-status">
                          {scanResult.tumor_detected ? "Detected" : "Not Detected"}
                        </p>
                      </div>
                      {scanResult.tumor_detected && (
                        <>
                          <div className="p-4 bg-white rounded-lg">
                            <p className="text-sm font-medium text-gray-600">Severity Level</p>
                            <p className="text-xl font-semibold" data-testid="severity-level">{scanResult.severity}</p>
                          </div>
                          <div className="p-4 bg-white rounded-lg">
                            <p className="text-sm font-medium text-gray-600">Recommended Specialist</p>
                            <p className="text-xl font-semibold" data-testid="recommended-specialist">{scanResult.doctor_specialization}</p>
                          </div>
                          {scanResult.recommended_doctor && (
                            <div className="p-4 bg-white rounded-lg">
                              <p className="text-sm font-medium text-gray-600">Suggested Doctor</p>
                              <p className="text-xl font-semibold" data-testid="recommended-doctor">{scanResult.recommended_doctor}</p>
                            </div>
                          )}
                        </>
                      )}
                      <div className="p-4 bg-white rounded-lg">
                        <p className="text-sm font-medium text-gray-600 mb-2">Detailed Analysis</p>
                        <ScrollArea className="h-48">
                          <p className="text-sm text-gray-700 whitespace-pre-line" data-testid="detailed-analysis">{scanResult.analysis_result}</p>
                        </ScrollArea>
                      </div>
                      <Button 
                        onClick={() => downloadReport(scanResult.id)} 
                        className="w-full"
                        data-testid="download-report-btn"
                      >
                        <FileText className="w-4 h-4 mr-2" />
                        Download PDF Report
                      </Button>
                    </CardContent>
                  </Card>
                )}
              </div>
            </TabsContent>

            <TabsContent value="history">
              <Card data-testid="history-card">
                <CardHeader>
                  <CardTitle>Scan History</CardTitle>
                  <CardDescription>View all your previous MRI scans and results</CardDescription>
                </CardHeader>
                <CardContent>
                  {scanHistory.length === 0 ? (
                    <p className="text-center text-gray-500 py-8" data-testid="no-history-msg">No scan history yet. Upload your first MRI scan to get started.</p>
                  ) : (
                    <div className="space-y-4">
                      {scanHistory.map((scan, index) => (
                        <Card key={scan.id} className="hover:shadow-md transition-shadow" data-testid={`history-item-${index}`}>
                          <CardContent className="p-4">
                            <div className="flex justify-between items-start">
                              <div className="flex-1">
                                <p className="text-sm text-gray-600">Scan Date: {new Date(scan.scan_date).toLocaleString()}</p>
                                <p className={`text-lg font-semibold mt-2 ${scan.tumor_detected ? 'text-red-600' : 'text-green-600'}`}>
                                  {scan.tumor_detected ? "Tumor Detected" : "No Tumor Detected"}
                                </p>
                                {scan.tumor_detected && (
                                  <p className="text-sm text-gray-700 mt-1">Severity: {scan.severity}</p>
                                )}
                              </div>
                              <Button onClick={() => downloadReport(scan.id)} size="sm" data-testid={`download-history-btn-${index}`}>
                                <FileText className="w-4 h-4 mr-1" />
                                Report
                              </Button>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="chat">
              <Card className="h-[600px] flex flex-col" data-testid="chat-card">
                <CardHeader>
                  <CardTitle>AI Health Assistant</CardTitle>
                  <CardDescription>Ask questions about brain health, MRI results, or medical information</CardDescription>
                </CardHeader>
                <CardContent className="flex-1 flex flex-col">
                  <ScrollArea className="flex-1 pr-4 mb-4">
                    {chatMessages.length === 0 ? (
                      <div className="text-center text-gray-500 py-12" data-testid="chat-welcome">
                        <MessageSquare className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                        <p>Hello! I'm your NeuroScan assistant. How can I help you today?</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {chatMessages.map((msg, index) => (
                          <div key={index} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`} data-testid={`chat-message-${index}`}>
                            <div className={`max-w-[80%] p-3 rounded-lg ${msg.role === 'user' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-800'}`}>
                              {msg.content}
                            </div>
                          </div>
                        ))}
                        {isChatLoading && (
                          <div className="flex justify-start" data-testid="chat-loading">
                            <div className="bg-gray-100 text-gray-800 p-3 rounded-lg">Typing...</div>
                          </div>
                        )}
                      </div>
                    )}
                  </ScrollArea>
                  <div className="flex gap-2">
                    <Textarea
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      placeholder="Ask a question..."
                      className="flex-1"
                      onKeyPress={(e) => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), handleChat())}
                      data-testid="chat-input"
                    />
                    <Button onClick={handleChat} disabled={isChatLoading || !chatInput.trim()} data-testid="chat-send-btn">
                      Send
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="doctors">
              <Card data-testid="doctors-card">
                <CardHeader>
                  <CardTitle>Available Specialists</CardTitle>
                  <CardDescription>Connect with experienced neurological specialists</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid md:grid-cols-2 gap-4">
                    {doctors.map((doctor, index) => (
                      <Card key={doctor.id || index} className="hover:shadow-lg transition-shadow" data-testid={`doctor-card-${index}`}>
                        <CardContent className="p-6">
                          <div className="flex items-start gap-4 mb-4">
                            <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-full flex items-center justify-center text-white text-2xl font-bold">
                              {doctor.name.charAt(0)}
                            </div>
                            <div className="flex-1">
                              <h3 className="text-xl font-semibold text-gray-800">{doctor.name}</h3>
                              <p className="text-blue-600 font-medium">{doctor.specialization}</p>
                              <p className="text-sm text-gray-600 mt-2">Experience: {doctor.experience}</p>
                              <p className="text-sm text-gray-600">Location: {doctor.location}</p>
                              <p className="text-sm text-gray-600">Contact: {doctor.contact}</p>
                              <p className="text-sm font-semibold text-yellow-600 mt-2">Rating: {doctor.rating} ⭐</p>
                            </div>
                          </div>
                          <BookAppointmentDialog doctor={doctor} onSuccess={loadAppointments} />
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="appointments">
              <Card data-testid="appointments-card">
                <CardHeader>
                  <CardTitle>My Appointments</CardTitle>
                  <CardDescription>View and manage your scheduled appointments</CardDescription>
                </CardHeader>
                <CardContent>
                  {appointments.length === 0 ? (
                    <p className="text-center text-gray-500 py-8" data-testid="no-appointments-msg">No appointments scheduled. Book an appointment with a specialist.</p>
                  ) : (
                    <div className="space-y-4">
                      {appointments.map((appointment, index) => (
                        <Card key={appointment.id} className="hover:shadow-md transition-shadow" data-testid={`appointment-item-${index}`}>
                          <CardContent className="p-4">
                            <div className="flex justify-between items-start">
                              <div className="flex-1">
                                <h3 className="text-lg font-semibold text-gray-800">{appointment.doctor_name}</h3>
                                <p className="text-sm text-blue-600">{appointment.doctor_specialization}</p>
                                <div className="mt-2 space-y-1">
                                  <p className="text-sm text-gray-600">
                                    <Calendar className="w-4 h-4 inline mr-1" />
                                    {appointment.appointment_date} at {appointment.appointment_time}
                                  </p>
                                  <p className="text-sm text-gray-600">Reason: {appointment.reason}</p>
                                  <p className={`text-sm font-medium ${appointment.status === 'Pending' ? 'text-yellow-600' : appointment.status === 'Confirmed' ? 'text-green-600' : 'text-red-600'}`}>
                                    Status: {appointment.status}
                                  </p>
                                </div>
                              </div>
                              {appointment.status === 'Pending' && (
                                <Button 
                                  onClick={() => handleCancelAppointment(appointment.id)} 
                                  variant="destructive" 
                                  size="sm"
                                  data-testid={`cancel-appointment-btn-${index}`}
                                >
                                  Cancel
                                </Button>
                              )}
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="profile">
              <Card data-testid="profile-card">
                <CardHeader>
                  <CardTitle>My Profile</CardTitle>
                  <CardDescription>Manage your personal information and medical history</CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleUpdateProfile} className="space-y-4">
                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="full_name">Full Name</Label>
                        <Input
                          id="full_name"
                          value={profileData.full_name}
                          onChange={(e) => setProfileData({ ...profileData, full_name: e.target.value })}
                          data-testid="profile-name-input"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="phone">Phone Number</Label>
                        <Input
                          id="phone"
                          value={profileData.phone}
                          onChange={(e) => setProfileData({ ...profileData, phone: e.target.value })}
                          placeholder="+1-555-0100"
                          data-testid="profile-phone-input"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="age">Age</Label>
                        <Input
                          id="age"
                          type="number"
                          value={profileData.age}
                          onChange={(e) => setProfileData({ ...profileData, age: parseInt(e.target.value) || '' })}
                          placeholder="30"
                          data-testid="profile-age-input"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="gender">Gender</Label>
                        <Select value={profileData.gender} onValueChange={(value) => setProfileData({ ...profileData, gender: value })}>
                          <SelectTrigger data-testid="profile-gender-select">
                            <SelectValue placeholder="Select gender" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="Male">Male</SelectItem>
                            <SelectItem value="Female">Female</SelectItem>
                            <SelectItem value="Other">Other</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="address">Address</Label>
                      <Input
                        id="address"
                        value={profileData.address}
                        onChange={(e) => setProfileData({ ...profileData, address: e.target.value })}
                        placeholder="123 Main St, City, State, ZIP"
                        data-testid="profile-address-input"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="medical_history">Medical History</Label>
                      <Textarea
                        id="medical_history"
                        value={profileData.medical_history}
                        onChange={(e) => setProfileData({ ...profileData, medical_history: e.target.value })}
                        placeholder="Any previous medical conditions, surgeries, or relevant medical history..."
                        rows={4}
                        data-testid="profile-medical-history-input"
                      />
                    </div>
                    <Button 
                      type="submit" 
                      className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
                      disabled={isUpdatingProfile}
                      data-testid="update-profile-btn"
                    >
                      {isUpdatingProfile ? 'Updating...' : 'Update Profile'}
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <div className="App">
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/signup" element={<SignupPage />} />
            <Route path="/dashboard" element={<Dashboard />} />
          </Routes>
        </BrowserRouter>
      </div>
    </AuthProvider>
  );
}

export default App;